// Scheduler process: ticks every IX_SCHEDULER_TICK_S seconds (default 15).
import { assertNoBrokerSecrets, loadAppEnv } from "../envfiles.ts";
import { log } from "../log.ts";
import { createRemoteBroker } from "../broker/remote.ts";
import { deliverAlerts } from "../security/alerts.ts";
import { runHygiene } from "../security/hygiene.ts";
import { createPool } from "../store/db.ts";
import { startBoss } from "./queue.ts";
import { createScheduler } from "./scheduler.ts";

loadAppEnv();
assertNoBrokerSecrets("scheduler");

const pool = createPool(process.env.DATABASE_URL_APP);
const boss = await startBoss(process.env.DATABASE_URL_APP!);
const scheduler = createScheduler({ pool, boss, log: (m) => log.info(m) });
const broker = createRemoteBroker(); // alert delivery only: the webhook URL is a secret the broker holds
const tickMs = Number(process.env.IX_SCHEDULER_TICK_S ?? 15) * 1000;

let running = false;
async function loop(): Promise<void> {
  if (running) return;
  running = true;
  try {
    const h = await runHygiene(pool);
    for (const id of h.disabled) log.warn({ connector: id }, "idle connector auto-disabled");
    const r = await scheduler.tick();
    for (const s of r.skipped) if (!s.reason.startsWith("no schedule")) log.debug({ connector: s.id, reason: s.reason }, "not scheduled");
    const d = await deliverAlerts(pool, broker).catch((e: Error) => {
      log.warn({ err: e.message }, "alert delivery failed");
      return null;
    });
    if (d && (d.sent || d.failed)) log.info(d, "alerts delivered");
  } catch (e) {
    log.error({ err: (e as Error).message }, "scheduler tick failed");
  } finally {
    running = false;
  }
}
const timer = setInterval(loop, tickMs);
await loop();
log.info({ tick_s: tickMs / 1000 }, "scheduler started");

for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, async () => {
    clearInterval(timer);
    await boss.stop({ graceful: true });
    await pool.end();
    process.exit(0);
  });
