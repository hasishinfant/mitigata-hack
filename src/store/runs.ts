// Postgres implementation of the engine's RunStore, plus run history queries.
import type pg from "pg";
import type { Checkpoint, FieldStats, PageCommit, RunStatus, RunStore } from "../engine/runner.ts";
import { withTx } from "./db.ts";
import { insertQuarantine } from "./quarantine.ts";
import { upsertRecords } from "./upsert.ts";

export function createPgRunStore(pool: pg.Pool): RunStore {
  return {
    async startRun(r) {
      await pool.query(
        "insert into runs (id, connector_id, stream, status, started_at, config_hash, resumed) values ($1, $2, $3, 'running', $4, $5, $6)",
        [r.runId, r.connectorId, r.stream, r.startedAt, r.configHash, r.resumed],
      );
    },

    async commitPage(p: PageCommit) {
      await withTx(pool, async (c) => {
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
        else await c.query("delete from checkpoints where connector_id = $1 and stream = $2", [p.connectorId, p.stream]);
      });
    },

    async finishRun(r) {
      await withTx(pool, async (c) => {
        // requests is authoritative here: failed requests never reach commitPage.
        await c.query(
          `update runs set status = $2, finished_at = now(), last_error = $3, requests = $4, retries = $5, rate_limited_ms = $6, field_stats = $7
           where id = $1`,
          [r.runId, r.status, r.lastError ?? null, r.requests, r.retries, r.rateLimitedMs, JSON.stringify(r.fieldStats)],
        );
        if (["success", "partial", "degraded"].includes(r.status))
          await c.query("update connectors set last_success_at = now() where id = $1", [r.connectorId]);
      });
    },

    async loadCheckpoint(connectorId, stream): Promise<Checkpoint | null> {
      const r = await pool.query("select page_state from checkpoints where connector_id = $1 and stream = $2", [connectorId, stream]);
      const ps = r.rows[0]?.page_state as { next_url?: string; next_body?: Record<string, unknown>; config_hash?: string } | undefined;
      if (!ps?.next_url) return null;
      return { nextUrl: ps.next_url, ...(ps.next_body ? { nextBody: ps.next_body } : {}), configHash: ps.config_hash ?? "" };
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
        "select status from runs where connector_id = $1 and status <> 'running' order by started_at desc, finished_at desc limit $2",
        [connectorId, n],
      );
      return r.rows.map((x) => x.status as RunStatus);
    },

    async pause(connectorId, until, reason) {
      await pool.query("update connectors set status = 'paused', paused_until = $2, disabled_reason = $3 where id = $1", [connectorId, until, reason]);
    },

    async resume(connectorId) {
      await pool.query(
        "update connectors set status = 'enabled', paused_until = null, disabled_reason = null where id = $1 and status = 'paused'",
        [connectorId],
      );
    },

    async raiseAlert(connectorId, kind, message) {
      await pool.query("insert into alerts (connector_id, kind, message) values ($1, $2, $3)", [connectorId, kind, message]);
    },
  };
}

export async function listRuns(pool: pg.Pool, connectorId: string, limit = 20) {
  const res = await pool.query(
    `select id, stream, status, started_at, finished_at, requests, records_ok, records_quarantined, retries, rate_limited_ms, resumed, last_error
     from runs where connector_id = $1 order by started_at desc limit $2`,
    [connectorId, limit],
  );
  return res.rows;
}
