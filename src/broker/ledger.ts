// Hash-chained audit ledger: every outbound call, policy denial, secret write and config registration.
// hash = sha256(prev_hash + canonical JSON of the row). The table is append-only (trigger + grants),
// and verifyLedger() recomputes the chain to detect edits, deletions or reordering.
import { createHash } from "node:crypto";
import type pg from "pg";

export const GENESIS = "0".repeat(64);
const LOCK_KEY = 74_201_106;

export type AuditEntry = {
  actor?: string;
  connectorId?: string | null;
  action: string; // request | token | register | secret_set | secret_delete | test
  method?: string | null;
  host?: string | null;
  path?: string | null; // path only, never the query string
  status?: number | null;
  records?: number | null;
  decision: string; // allow | deny: <reason> | error: <kind>
};

type Row = Required<{ [K in keyof AuditEntry]: AuditEntry[K] | null }> & { ts: string };

export function canonical(row: Row): string {
  const keys = ["ts", "actor", "connector_id", "action", "method", "host", "path", "status", "records", "decision"] as const;
  const obj: Record<string, unknown> = {
    ts: row.ts, actor: row.actor, connector_id: row.connectorId, action: row.action, method: row.method,
    host: row.host, path: row.path, status: row.status, records: row.records, decision: row.decision,
  };
  return JSON.stringify(Object.fromEntries(keys.map((k) => [k, obj[k] ?? null])));
}
export const chainHash = (prev: string, row: Row) => createHash("sha256").update(prev + canonical(row)).digest("hex");

export async function appendLedger(pool: pg.Pool, e: AuditEntry): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("select pg_advisory_xact_lock($1)", [LOCK_KEY]); // serialise appends across broker instances
    const prev = ((await client.query("select hash from audit_ledger order by seq desc limit 1")).rows[0]?.hash as string | undefined) ?? GENESIS;
    const row: Row = {
      ts: new Date().toISOString(), actor: e.actor ?? "broker", connectorId: e.connectorId ?? null, action: e.action,
      method: e.method ?? null, host: e.host ?? null, path: e.path ?? null, status: e.status ?? null, records: e.records ?? null,
      decision: e.decision,
    };
    await client.query(
      `insert into audit_ledger (ts, actor, connector_id, action, method, host, path, status, records, decision, prev_hash, hash)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [row.ts, row.actor, row.connectorId, row.action, row.method, row.host, row.path, row.status, row.records, row.decision, prev, chainHash(prev, row)],
    );
    await client.query("commit");
  } catch (err) {
    await client.query("rollback").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export type LedgerCheck = { ok: boolean; rows: number; firstBadSeq?: number; problem?: string };

export async function verifyLedger(pool: pg.Pool): Promise<LedgerCheck> {
  const rows = (await pool.query("select * from audit_ledger order by seq")).rows;
  let prev = GENESIS;
  let lastSeq = 0;
  for (const r of rows) {
    const seq = Number(r.seq);
    if (seq !== lastSeq + 1 && lastSeq !== 0) return { ok: false, rows: rows.length, firstBadSeq: seq, problem: `gap before seq ${seq} (rows deleted?)` };
    if (r.prev_hash !== prev) return { ok: false, rows: rows.length, firstBadSeq: seq, problem: `seq ${seq} does not link to the previous row` };
    const row: Row = {
      ts: r.ts, actor: r.actor, connectorId: r.connector_id, action: r.action, method: r.method, host: r.host, path: r.path,
      status: r.status, records: r.records, decision: r.decision,
    };
    if (chainHash(prev, row) !== r.hash) return { ok: false, rows: rows.length, firstBadSeq: seq, problem: `seq ${seq} was modified after it was written` };
    prev = r.hash;
    lastSeq = seq;
  }
  return { ok: true, rows: rows.length };
}
