// Worker process. Holds no secrets: every provider call goes through the broker socket.
// IX_WORKER_CONCURRENCY connectors run in parallel (default 4).
import { createRemoteBroker } from "../broker/remote.ts";
import { assertNoBrokerSecrets, loadAppEnv } from "../envfiles.ts";
import { log } from "../log.ts";
import { RUN_QUEUE, startBoss, type RunJob } from "../scheduler/queue.ts";
import { createPool } from "../store/db.ts";
import { createWorker } from "./worker.ts";

loadAppEnv();
assertNoBrokerSecrets("worker");

const pool = createPool(process.env.DATABASE_URL_APP);
const worker = createWorker({ pool, broker: createRemoteBroker() });
const boss = await startBoss(process.env.DATABASE_URL_APP!, { supervise: true });
const concurrency = Number(process.env.IX_WORKER_CONCURRENCY ?? 4);

await boss.work<RunJob>(RUN_QUEUE, { batchSize: 1, localConcurrency: concurrency, pollingIntervalSeconds: 2 }, async ([job]) => {
  if (job) await worker.handle(job.data);
});
log.info({ concurrency }, "worker started (no secrets in this process)");

for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, async () => {
    await boss.stop({ graceful: true, timeout: 30_000 });
    await pool.end();
    process.exit(0);
  });
