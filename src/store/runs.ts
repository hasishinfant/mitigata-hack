// Postgres implementation of the engine's RunStore, plus run history queries.
import type pg from "pg";
import type { PageCommit, RunStore } from "../engine/runner.ts";
import { withTx } from "./db.ts";
import { insertQuarantine } from "./quarantine.ts";
import { upsertRecords } from "./upsert.ts";

export function createPgRunStore(pool: pg.Pool): RunStore {
  return {
    async startRun(r) {
      await pool.query(
        "insert into runs (id, connector_id, stream, status, started_at, config_hash) values ($1, $2, $3, 'running', $4, $5)",
        [r.runId, r.connectorId, r.stream, r.startedAt, r.configHash],
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
      });
    },
    async finishRun(r) {
      await withTx(pool, async (c) => {
        // requests is authoritative here: failed requests never reach commitPage.
        await c.query("update runs set status = $2, finished_at = now(), last_error = $3, requests = $4 where id = $1", [
          r.runId, r.status, r.lastError ?? null, r.requests,
        ]);
        if (r.status === "success" || r.status === "partial")
          await c.query("update connectors set last_success_at = now() where id = $1", [r.connectorId]);
      });
    },
  };
}

export async function listRuns(pool: pg.Pool, connectorId: string, limit = 20) {
  const res = await pool.query(
    `select id, stream, status, started_at, finished_at, requests, records_ok, records_quarantined, retries, last_error
     from runs where connector_id = $1 order by started_at desc limit $2`,
    [connectorId, limit],
  );
  return res.rows;
}
