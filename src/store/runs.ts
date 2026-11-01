// Postgres implementation of the engine's RunStore, plus run history queries.
import type pg from "pg";
import type pgTypes from "pg";
import { LOCK_LOST, RunFailure, type Checkpoint, type FieldStats, type FinishedRun, type PageCommit, type RunStatus, type RunStore } from "../engine/runner.ts";
import { withTx } from "./db.ts";
import { insertQuarantine } from "./quarantine.ts";
import { upsertRecords } from "./upsert.ts";
import { raiseAlertOnce } from "../security/alerts.ts";
import { acquireRunLock, LockLost, type RunLock } from "./runLock.ts";

export type PgRunStoreOptions = {
  /** Test hook: called inside a write transaction after its writes, just before COMMIT. */
  beforeCommit?: (kind: "page" | "finish", connectorId: string) => Promise<void>;
};

export function createPgRunStore(pool: pg.Pool, opts: PgRunStoreOptions = {}): RunStore {
  const held = new Map<string, RunLock>(); // connector -> the run lock this store's run holds
  const LOST = `${LOCK_LOST} (its database session ended); nothing more was committed`;

  /**
   * A run's writes go through the lock-holding session when the run holds a lock (single-flight is then a property
   * of the transaction itself: see runLock.ts), otherwise through the data pool (stores used without runConnector).
   */
  const write = async <T>(connectorId: string, fn: (c: pgTypes.PoolClient) => Promise<T>): Promise<T> => {
    const lock = held.get(connectorId);
    if (!lock) return withTx(pool, fn);
    try {
      return await lock.tx(fn);
    } catch (e) {
      if (e instanceof LockLost) throw new RunFailure("failed", LOST);
      throw e;
    }
  };

  return {
    async startRun(r) {
      await pool.query(
        "insert into runs (id, connector_id, stream, status, started_at, config_hash, resumed, trigger) values ($1, $2, $3, 'running', $4, $5, $6, $7)",
        [r.runId, r.connectorId, r.stream, r.startedAt, r.configHash, r.resumed, r.trigger],
      );
    },

    async commitPage(p: PageCommit) {
      await write(p.connectorId, async (c) => {
        await upsertRecords(c, p.entity, p.records, {
          tenant: p.tenant, source: p.source, connectorId: p.connectorId, runId: p.runId, fetchedAt: p.fetchedAt,
        });
        await insertQuarantine(c, p.runId, p.connectorId, p.quarantined);
        await c.query(
          `update runs set requests = requests + $2, records_ok = records_ok + $3, records_quarantined = records_quarantined + $4
           where id = $1`,
          [p.runId, p.requests, p.records.length, p.quarantined.length],
        );
        // Checkpoint commits with the page: a crash can never skip or double-count a page.
        if (p.checkpoint)
          await c.query(
            `insert into checkpoints (connector_id, stream, page_state, updated_at) values ($1, $2, $3, now())
             on conflict (connector_id, stream) do update set page_state = excluded.page_state, updated_at = now()`,
            [p.connectorId, p.stream, JSON.stringify({ next_url: p.checkpoint.nextUrl, next_body: p.checkpoint.nextBody, config_hash: p.checkpoint.configHash })],
          );
        // Stream complete: clear the page position but keep the row (it holds the incremental watermark).
        else await c.query("update checkpoints set page_state = null, updated_at = now() where connector_id = $1 and stream = $2", [p.connectorId, p.stream]);
        await opts.beforeCommit?.("page", p.connectorId);
      });
    },

    // Status and watermark in one transaction, on the lock session. If it fails (or the lock session dies before
    // COMMIT), neither is saved. If the lock was lost, only the run's own history row is marked failed, through the
    // data pool: no records, checkpoints, watermark or connector state, so it cannot interfere with a replacement run.
    async finishRun(r): Promise<FinishedRun> {
      try {
        return await write(r.connectorId, async (c) => {
          if (r.watermark)
            // Only cursor_value: the page position (page_state) is left as the last page commit wrote it.
            await c.query(
              `insert into checkpoints (connector_id, stream, cursor_value, updated_at) values ($1, $2, $3, now())
               on conflict (connector_id, stream) do update set cursor_value = excluded.cursor_value, updated_at = now()`,
              [r.connectorId, r.stream, r.watermark],
            );
          // requests is authoritative here: failed requests never reach commitPage.
          await c.query(
            `update runs set status = $2, finished_at = now(), last_error = $3, requests = $4, retries = $5, rate_limited_ms = $6, field_stats = $7
             where id = $1`,
            [r.runId, r.status, r.lastError ?? null, r.requests, r.retries, r.rateLimitedMs, JSON.stringify(r.fieldStats)],
          );
          if (["success", "partial", "degraded"].includes(r.status))
            await c.query("update connectors set last_success_at = now() where id = $1", [r.connectorId]);
          await opts.beforeCommit?.("finish", r.connectorId);
          return { status: r.status, ...(r.lastError !== undefined ? { lastError: r.lastError } : {}), watermarkSaved: Boolean(r.watermark) };
        });
      } catch (e) {
        if (!(e instanceof RunFailure && e.message === LOST)) throw e;
        const lastError = `${LOST}; ${r.watermark ? "watermark not advanced; " : ""}run marked failed`;
        await pool.query("update runs set status = 'failed', finished_at = now(), last_error = $2, requests = $3, retries = $4, rate_limited_ms = $5 where id = $1", [
          r.runId, lastError, r.requests, r.retries, r.rateLimitedMs,
        ]);
        return { status: "failed", lastError, watermarkSaved: false };
      }
    },

    async loadCheckpoint(connectorId, stream): Promise<Checkpoint | null> {
      const r = await pool.query("select page_state, cursor_value from checkpoints where connector_id = $1 and stream = $2", [connectorId, stream]);
      if (!r.rowCount) return null;
      const ps = r.rows[0].page_state as { next_url?: string; next_body?: Record<string, unknown>; config_hash?: string } | null;
      const cursorValue = (r.rows[0].cursor_value as string | null) ?? undefined;
      if (!ps?.next_url && !cursorValue) return null;
      return {
        ...(ps?.next_url ? { nextUrl: ps.next_url } : {}),
        ...(ps?.next_body ? { nextBody: ps.next_body } : {}),
        configHash: ps?.config_hash ?? "",
        ...(cursorValue ? { cursorValue } : {}),
      };
    },

    async previousFieldStats(connectorId, stream, excludeRunId): Promise<FieldStats | null> {
      const r = await pool.query(
        `select field_stats from runs where connector_id = $1 and stream = $2 and id <> $3
         and status in ('success', 'partial') and field_stats is not null order by started_at desc limit 1`,
        [connectorId, stream, excludeRunId],
      );
      return (r.rows[0]?.field_stats as FieldStats | undefined) ?? null;
    },

    async connectorState(connectorId) {
      const r = await pool.query("select status, paused_until, disabled_reason from connectors where id = $1", [connectorId]);
      if (!r.rowCount) throw new Error(`connector ${connectorId} not found`);
      const row = r.rows[0];
      return { status: row.status as string, pausedUntil: row.paused_until ? new Date(row.paused_until) : null, reason: row.disabled_reason ?? null };
    },

    async recentStatuses(connectorId, n): Promise<RunStatus[]> {
      const r = await pool.query(
        // Lock-loss failures are coordination failures, not provider failures: they don't count in a streak.
        `select status from runs where connector_id = $1 and status <> 'running'
           and not (status = 'failed' and coalesce(last_error, '') like $3)
         order by started_at desc, finished_at desc limit $2`,
        [connectorId, n, `${LOCK_LOST}%`],
      );
      return r.rows.map((x) => x.status as RunStatus);
    },

    async pause(connectorId, until, reason) {
      // Never over a disabled connector: a breaker must not turn "disabled" into "paused" (and later "enabled").
      await pool.query("update connectors set status = 'paused', paused_until = $2, disabled_reason = $3 where id = $1 and status <> 'disabled'", [
        connectorId, until, reason,
      ]);
    },

    async resume(connectorId) {
      await pool.query(
        "update connectors set status = 'enabled', paused_until = null, disabled_reason = null where id = $1 and status = 'paused'",
        [connectorId],
      );
    },

    // De-duplicated per connector and kind for an hour, so a bad key on a 15-minute schedule doesn't spam.
    async raiseAlert(connectorId, kind, message) {
      await raiseAlertOnce(pool, connectorId, kind, message, 1);
    },

    async lockConnector(connectorId) {
      const lock = await acquireRunLock(pool, connectorId);
      if (!lock) return null;
      held.set(connectorId, lock);
      return {
        check: async () => {
          try {
            await lock.check();
          } catch (e) {
            if (e instanceof LockLost) throw new RunFailure("failed", LOST);
            throw e;
          }
        },
        release: async () => {
          if (held.get(connectorId) === lock) held.delete(connectorId);
          await lock.release();
        },
      };
    },
  };
}

export async function listRuns(pool: pg.Pool, connectorId: string, limit = 20) {
  const res = await pool.query(
    `select id, stream, status, started_at, finished_at, requests, records_ok, records_quarantined, retries, rate_limited_ms, resumed, trigger, last_error
     from runs where connector_id = $1 order by started_at desc limit $2`,
    [connectorId, limit],
  );
  return res.rows;
}
