// Bad records with their errors. Raw payloads are secret-scanned before storage.
import type pg from "pg";
import { redactValue } from "../mapping/scanner.ts";
import type { QuarantineItem } from "../engine/runner.ts";

const MAX_RAW_BYTES = 32 * 1024;

export async function insertQuarantine(client: pg.ClientBase, runId: string, connectorId: string, items: QuarantineItem[]): Promise<void> {
  for (const item of items) {
    let raw: unknown = redactValue(item.raw);
    const text = JSON.stringify(raw) ?? "null";
    if (text.length > MAX_RAW_BYTES) raw = { truncated: true, preview: text.slice(0, MAX_RAW_BYTES) };
    await client.query("insert into quarantine (run_id, connector_id, raw_redacted, errors) values ($1, $2, $3, $4)", [
      runId, connectorId, JSON.stringify(raw), JSON.stringify(item.errors),
    ]);
  }
}

export async function listQuarantine(pool: pg.Pool, opts: { connectorId?: string; limit?: number }) {
  const res = await pool.query(
    `select id, run_id, connector_id, errors, raw_redacted, created_at from quarantine
     where ($1::text is null or connector_id = $1) order by id desc limit $2`,
    [opts.connectorId ?? null, opts.limit ?? 50],
  );
  return res.rows;
}
