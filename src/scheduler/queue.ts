// Job queue (pg-boss on Postgres). One queue, "exclusive" policy keyed by connector id:
// at most one queued-or-running job per connector, so a slow run can never pile up behind itself.
import { PgBoss } from "pg-boss";
import type { RunTrigger } from "../engine/runner.ts";

export const RUN_QUEUE = "run-connector";
export type RunJob = { connectorId: string; trigger: RunTrigger };

export async function startBoss(connectionString: string, opts: { supervise?: boolean } = {}): Promise<PgBoss> {
  const boss = new PgBoss({ connectionString, schema: "pgboss", supervise: opts.supervise ?? false, schedule: false });
  boss.on("error", (e: Error) => console.error(`queue error: ${e.message}`));
  await boss.start();
  if (!(await boss.getQueue(RUN_QUEUE))) {
    await boss.createQueue(RUN_QUEUE, { policy: "exclusive", retryLimit: 0, expireInSeconds: 3600 });
  }
  return boss;
}

/** Enqueue a run. Returns the job id, or null if one is already queued or running for this connector. */
export async function enqueueRun(boss: PgBoss, job: RunJob): Promise<string | null> {
  return boss.send(RUN_QUEUE, job, { singletonKey: job.connectorId, retryLimit: 0, expireInSeconds: 3600 });
}
