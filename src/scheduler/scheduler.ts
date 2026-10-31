// Scheduler: turns each connector's `schedule.every` (+ jitter) into queued runs.
// State lives in connectors.next_run_at, so restarts don't lose or double schedules.
// A Postgres advisory lock makes sure only one scheduler acts per tick, even with several running.
import type { PgBoss } from "pg-boss";
import type pg from "pg";
import { loadActiveConnector } from "../store/connectors.ts";
import { enqueueRun } from "./queue.ts";

const LOCK_KEY = 74_201_105; // arbitrary constant for pg_try_advisory_lock

export type TickResult = { enqueued: string[]; skipped: { id: string; reason: string }[] };

export function nextRunAt(fromMs: number, everyMs: number, jitterMs: number, random: () => number = Math.random): Date {
  return new Date(fromMs + everyMs + Math.floor(random() * jitterMs));
}

export function createScheduler(opts: {
  pool: pg.Pool;
  boss: PgBoss;
  now?: () => number;
  random?: () => number;
  env?: Record<string, string | undefined>;
  log?: (msg: string) => void;
}) {
  const now = opts.now ?? Date.now;
  const random = opts.random ?? Math.random;
  const say = opts.log ?? (() => {});

  async function tick(): Promise<TickResult> {
    const out: TickResult = { enqueued: [], skipped: [] };
    const client = await opts.pool.connect();
    try {
      const locked = (await client.query("select pg_try_advisory_lock($1) as ok", [LOCK_KEY])).rows[0].ok as boolean;
      if (!locked) return out;
      try {
        const rows = (
          await client.query("select id, status, paused_until, next_run_at from connectors where status in ('enabled', 'paused') order by id")
        ).rows as { id: string; status: string; paused_until: Date | null; next_run_at: Date | null }[];
        const t = now();
        for (const row of rows) {
          let conn;
          try {
            conn = await loadActiveConnector(opts.pool, row.id, opts.env);
          } catch (e) {
            out.skipped.push({ id: row.id, reason: `config: ${(e as Error).message}` });
            continue;
          }
          const sched = conn.runtime.schedule;
          if (!sched) {
            out.skipped.push({ id: row.id, reason: "no schedule" });
            continue;
          }
          // First sighting: run soon (within the jitter window) rather than waiting a full interval.
          if (!row.next_run_at) {
            const first = new Date(t + Math.floor(random() * sched.jitterMs));
            await client.query("update connectors set next_run_at = $2 where id = $1", [row.id, first]);
            row.next_run_at = first;
          }
          if (new Date(row.next_run_at).getTime() > t) continue;
          if (row.status === "paused" && row.paused_until && new Date(row.paused_until).getTime() > t) {
            await client.query("update connectors set next_run_at = $2 where id = $1", [row.id, row.paused_until]);
            out.skipped.push({ id: row.id, reason: "circuit open" });
            continue;
          }
          const jobId = await enqueueRun(opts.boss, { connectorId: row.id, trigger: "schedule" });
          await client.query("update connectors set next_run_at = $2 where id = $1", [row.id, nextRunAt(t, sched.everyMs, sched.jitterMs, random)]);
          if (jobId) {
            out.enqueued.push(row.id);
            say(`enqueued ${row.id}`);
          } else out.skipped.push({ id: row.id, reason: "previous run still queued or running" });
        }
      } finally {
        await client.query("select pg_advisory_unlock($1)", [LOCK_KEY]);
      }
    } finally {
      client.release();
    }
    return out;
  }

  return { tick };
}
