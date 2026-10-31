// Worker process. IX_WORKER_CONCURRENCY connectors run in parallel (default 4).
import { chainSecretSources, dbSecretSource, envSecretSource, parseMasterKey } from "../broker/secrets.ts";
import type { SecretSource } from "../broker/types.ts";
import { log } from "../log.ts";
import { RUN_QUEUE, startBoss, type RunJob } from "../scheduler/queue.ts";
import { createPool } from "../store/db.ts";
import { createWorker } from "./worker.ts";

try { process.loadEnvFile(); } catch { /* no .env is fine */ }

const pool = createPool(process.env.DATABASE_URL_APP);
const sources: SecretSource[] = [];
let brokerPool: ReturnType<typeof createPool> | undefined;
if (process.env.DATABASE_URL_BROKER && process.env.IX_MASTER_KEY) {
  brokerPool = createPool(process.env.DATABASE_URL_BROKER, "DATABASE_URL_BROKER");
  sources.push(dbSecretSource(brokerPool, parseMasterKey(process.env.IX_MASTER_KEY)));
}
sources.push(envSecretSource());

const worker = createWorker({ pool, secrets: chainSecretSources(...sources) });
const boss = await startBoss(process.env.DATABASE_URL_APP!, { supervise: true });
const concurrency = Number(process.env.IX_WORKER_CONCURRENCY ?? 4);

await boss.work<RunJob>(RUN_QUEUE, { batchSize: 1, localConcurrency: concurrency, pollingIntervalSeconds: 2 }, async ([job]) => {
  if (job) await worker.handle(job.data);
});
log.info({ concurrency }, "worker started");

for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, async () => {
    await boss.stop({ graceful: true, timeout: 30_000 });
    await pool.end();
    await brokerPool?.end();
    process.exit(0);
  });
