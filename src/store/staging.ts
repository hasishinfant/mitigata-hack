// Staged ingestion (T7) and Sync Integrity Receipts (T8), Postgres side.
// Every function here runs inside a transaction the caller owns; for a run, that is a transaction on the run's
// lock-holding session (runLock.ts), so staging, promotion and receipts share the single-flight guarantee.
import type pg from "pg";
import type { Entity } from "../config/schema.ts";
import type { MappedRecord } from "../mapping/mapper.ts";
import { receiptDigest } from "../engine/receipt.ts";
import { acquireRunLock } from "./runLock.ts";
import { upsertRecords } from "./upsert.ts";

const BATCH = 1000;

/** Stage one page. A fresh sync first discards older open (never held) staging of the same stream. */
export async function stagePage(
  c: pg.PoolClient,
  p: { syncId: string; freshSync: boolean; connectorId: string; stream: string; entity: Entity; runId: string; fetchedAt: Date; records: MappedRecord[] },
): Promise<void> {
  if (p.freshSync)
    await c.query("delete from stage_syncs where connector_id = $1 and stream = $2 and state = 'open' and sync_id <> $3", [p.connectorId, p.stream, p.syncId]);
  await c.query("insert into stage_syncs (sync_id, connector_id, stream) values ($1, $2, $3) on conflict (sync_id) do nothing", [p.syncId, p.connectorId, p.stream]);
  // Last occurrence wins within a sync (same as the common tables).
  const unique = [...new Map(p.records.map((r) => [r.sourceId, r])).values()];
  for (let i = 0; i < unique.length; i += BATCH) {
    const chunk = unique.slice(i, i + BATCH);
    const values: unknown[] = [];
    const rows = chunk.map((r) => {
      const b = values.length;
      values.push(p.syncId, p.entity, r.sourceId, JSON.stringify(r.fields), JSON.stringify(r.attributes), p.runId, p.fetchedAt);
      return `($${b + 1}, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5}, $${b + 6}, $${b + 7})`;
    });
    await c.query(
      `insert into stage_records (sync_id, entity, source_id, fields, attributes, run_id, fetched_at) values ${rows.join(", ")}
       on conflict (sync_id, entity, source_id) do update
         set fields = excluded.fields, attributes = excluded.attributes, run_id = excluded.run_id, fetched_at = excluded.fetched_at`,
      values,
    );
  }
}

/** Promote every staged record of a sync into the common tables, then drop the staging. Returns records promoted. */
export async function promoteSync(c: pg.PoolClient, syncId: string): Promise<number> {
  const s = (
    await c.query(
      `select s.connector_id, k.tenant_id, k.source from stage_syncs s join connectors k on k.id = s.connector_id where s.sync_id = $1`,
      [syncId],
    )
  ).rows[0] as { connector_id: string; tenant_id: string; source: string } | undefined;
  if (!s) return 0;
  let n = 0;
  let after = "";
  for (;;) {
    const rows = (
      await c.query(
        `select entity, source_id, fields, attributes, run_id, fetched_at from stage_records
         where sync_id = $1 and source_id > $2 order by source_id limit $3`,
        [syncId, after, BATCH],
      )
    ).rows as { entity: Entity; source_id: string; fields: Record<string, unknown>; attributes: Record<string, unknown>; run_id: string; fetched_at: string }[];
    if (!rows.length) break;
    // Keep each record's own run and fetch time: group by (entity, run, fetched_at), i.e. by staged page.
    const groups = new Map<string, typeof rows>();
    for (const r of rows) {
      const k = `${r.entity}\u0000${r.run_id}\u0000${r.fetched_at}`;
      groups.set(k, [...(groups.get(k) ?? []), r]);
    }
    for (const g of groups.values()) {
      const first = g[0]!;
      await upsertRecords(c, first.entity, g.map((r) => ({ sourceId: r.source_id, fields: r.fields, attributes: r.attributes })), {
        tenant: s.tenant_id, source: s.source, connectorId: s.connector_id, runId: first.run_id, fetchedAt: new Date(first.fetched_at),
      });
    }
    n += rows.length;
    after = rows[rows.length - 1]!.source_id;
  }
  await c.query("delete from stage_syncs where sync_id = $1", [syncId]); // cascades the staged rows
  return n;
}

export async function discardSync(c: pg.PoolClient, syncId: string): Promise<number> {
  const n = Number((await c.query("select count(*) from stage_records where sync_id = $1", [syncId])).rows[0].count);
  await c.query("delete from stage_syncs where sync_id = $1", [syncId]);
  return n;
}

export async function holdSync(c: pg.PoolClient, syncId: string, reason: string): Promise<void> {
  await c.query("update stage_syncs set state = 'held', held_reason = $2 where sync_id = $1", [syncId, reason.slice(0, 2000)]);
}

/** Insert a receipt. Adds the active config version, then digests the canonical body. */
export async function insertReceipt(
  c: pg.PoolClient,
  r: { syncId: string; runId: string | null; connectorId: string; stream: string; kind: "run" | "approve" | "discard"; decision: string; published: boolean; body: Record<string, unknown> },
): Promise<{ id: number; digest: string }> {
  const version = (await c.query("select active_version from connectors where id = $1", [r.connectorId])).rows[0]?.active_version ?? null;
  const body = { ...r.body, connector: { ...((r.body.connector as Record<string, unknown> | undefined) ?? { id: r.connectorId }), config_version: version }, published: r.published };
  const digest = receiptDigest(body);
  const id = Number(
    (
      await c.query(
        `insert into sync_receipts (sync_id, run_id, connector_id, stream, kind, decision, published, body, digest)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9) returning id`,
        [r.syncId, r.runId, r.connectorId, r.stream, r.kind, r.decision, r.published, JSON.stringify(body), digest],
      )
    ).rows[0].id,
  );
  return { id, digest };
}

/** Raw-record schema of the last published sync of a stream (fingerprint baseline). */
export async function baselineSchema(pool: pg.Pool, connectorId: string, stream: string): Promise<Record<string, string[]> | null> {
  const r = await pool.query(
    `select body->'schema'->'shape' as shape from sync_receipts
     where connector_id = $1 and stream = $2 and kind = 'run' and published and (body->'schema'->>'sampled_records')::int > 0
     order by id desc limit 1`,
    [connectorId, stream],
  );
  return (r.rows[0]?.shape as Record<string, string[]> | undefined) ?? null;
}

export class SyncNotHeld extends Error {}

/**
 * Operator decision on a held sync (ix approve / ix discard). Takes the connector's run lock, so it can't race a run.
 * Approval is refused if a newer sync of the same stream was published since: promoting older data over newer
 * data would silently roll records back.
 */
export async function resolveHeldSync(
  pool: pg.Pool,
  syncId: string,
  action: "approve" | "discard",
  actor: string,
): Promise<{ receiptId: number; digest: string; records: number; connectorId: string }> {
  const s = (await pool.query("select connector_id, stream, state, held_reason, created_at from stage_syncs where sync_id = $1", [syncId])).rows[0] as
    | { connector_id: string; stream: string; state: string; held_reason: string | null; created_at: string }
    | undefined;
  if (!s || s.state !== "held") throw new SyncNotHeld(`sync ${syncId} is not held for review`);
  const lock = await acquireRunLock(pool, s.connector_id);
  if (!lock) throw new Error(`connector ${s.connector_id} is running; try again when the run has finished`);
  try {
    return await lock.tx(async (c) => {
      const still = (await c.query("select state from stage_syncs where sync_id = $1 for update", [syncId])).rows[0];
      if (still?.state !== "held") throw new SyncNotHeld(`sync ${syncId} is no longer held`);
      if (action === "approve") {
        const newer = (
          await c.query(
            "select id from sync_receipts where connector_id = $1 and stream = $2 and published and created_at > $3 limit 1",
            [s.connector_id, s.stream, s.created_at],
          )
        ).rows[0];
        if (newer) throw new Error(`a newer sync of ${s.connector_id}/${s.stream} was published since (receipt #${newer.id}); discard this one instead`);
      }
      const records = action === "approve" ? await promoteSync(c, syncId) : await discardSync(c, syncId);
      const prior = (await c.query("select id, digest from sync_receipts where sync_id = $1 order by id", [syncId])).rows;
      const { id, digest } = await insertReceipt(c, {
        syncId, runId: null, connectorId: s.connector_id, stream: s.stream, kind: action, decision: action === "approve" ? "approved" : "discarded",
        published: action === "approve",
        body: {
          receipt_version: 1, sync_id: syncId, connector: { id: s.connector_id }, stream: { name: s.stream },
          decision: action === "approve" ? "approved" : "discarded", actor, at: new Date().toISOString(), held_reason: s.held_reason,
          records: { [action === "approve" ? "promoted" : "discarded"]: records }, prior_receipts: prior,
        },
      });
      return { receiptId: id, digest, records, connectorId: s.connector_id };
    });
  } finally {
    await lock.release();
  }
}

export type ReceiptCheck = { id: number; digestMatches: boolean; anchored: boolean; anchorMatches: boolean | null };

/** Recompute a receipt's digest and compare it with the stored digest and with its ledger anchor. */
export async function verifyReceipt(pool: pg.Pool, id: number): Promise<ReceiptCheck | null> {
  const r = (await pool.query("select id, body, digest, anchored_seq from sync_receipts where id = $1", [id])).rows[0];
  if (!r) return null;
  const digestMatches = receiptDigest(r.body) === r.digest;
  if (!r.anchored_seq) return { id, digestMatches, anchored: false, anchorMatches: null };
  const l = (await pool.query("select decision from audit_ledger where seq = $1 and action = 'receipt'", [r.anchored_seq])).rows[0];
  return { id, digestMatches, anchored: true, anchorMatches: Boolean(l && String(l.decision).includes(`sha256:${receiptDigest(r.body)}`)) };
}

/** Receipt summaries for a connector, newest first (the full body is fetched per receipt). */
export async function listReceipts(pool: pg.Pool, connectorId: string, limit = 20) {
  return (
    await pool.query(
      `select id, sync_id, run_id, stream, kind, decision, published, created_at, anchored_seq, digest,
              (body->>'records_published')::int as records_published, body->'reasons' as reasons,
              body->'counts'->'sync' as sync_counts, body->'schema'->>'fingerprint' as fingerprint
       from sync_receipts where connector_id = $1 order by id desc limit $2`,
      [connectorId, limit],
    )
  ).rows;
}

/** Syncs held for review, with what they would publish. */
export async function listHeld(pool: pg.Pool, connectorId?: string) {
  return (
    await pool.query(
      `select s.sync_id, s.connector_id, s.stream, s.held_reason, s.created_at, count(r.source_id)::int as records
       from stage_syncs s left join stage_records r using (sync_id)
       where s.state = 'held' and ($1::text is null or s.connector_id = $1)
       group by s.sync_id order by s.created_at desc`,
      [connectorId ?? null],
    )
  ).rows;
}

/** Latest integrity decision per stream, and held count, per connector (health / dashboard). */
export async function integritySummary(pool: pg.Pool): Promise<Map<string, { streams: { stream: string; decision: string; published: boolean; receipt_id: number; at: string; anchored: boolean }[]; held: number }>> {
  const out = new Map<string, { streams: { stream: string; decision: string; published: boolean; receipt_id: number; at: string; anchored: boolean }[]; held: number }>();
  const latest = (
    await pool.query(
      `select distinct on (connector_id, stream) connector_id, stream, decision, published, id, created_at, anchored_seq is not null as anchored
       from sync_receipts order by connector_id, stream, id desc`,
    )
  ).rows;
  for (const r of latest) {
    const e = out.get(r.connector_id) ?? { streams: [], held: 0 };
    e.streams.push({ stream: r.stream, decision: r.decision, published: r.published, receipt_id: Number(r.id), at: r.created_at, anchored: r.anchored });
    out.set(r.connector_id, e);
  }
  for (const r of (await pool.query("select connector_id, count(*)::int as n from stage_syncs where state = 'held' group by 1")).rows) {
    const e = out.get(r.connector_id) ?? { streams: [], held: 0 };
    e.held = r.n;
    out.set(r.connector_id, e);
  }
  return out;
}
