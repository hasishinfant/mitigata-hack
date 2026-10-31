// Idempotent upserts into users / devices / events keyed by (tenant_id, source, source_id).
// Re-running a page never duplicates rows.
import type pg from "pg";
import type { Entity } from "../config/schema.ts";
import type { MappedRecord } from "../mapping/mapper.ts";

export const ENTITY_TABLE: Record<Entity, string> = { user: "users", device: "devices", event: "events" };

// mapping field -> column
const COLUMNS: Record<Entity, [field: string, column: string][]> = {
  user: [["name", "name"], ["email", "email"], ["status", "status"], ["last_login", "last_login"]],
  device: [["hostname", "hostname"], ["ip", "ip"], ["os", "os"], ["owner", "owner"], ["last_seen", "last_seen"]],
  event: [["type", "type"], ["severity", "severity"], ["timestamp", "ts"], ["description", "description"]],
};
const BATCH = 1000;

export type UpsertMeta = { tenant: string; source: string; connectorId: string; runId: string; fetchedAt: Date };

export async function upsertRecords(client: pg.ClientBase, entity: Entity, records: MappedRecord[], meta: UpsertMeta): Promise<number> {
  // Last occurrence wins if a provider returns the same id twice in one page.
  const unique = [...new Map(records.map((r) => [r.sourceId, r])).values()];
  const cols = COLUMNS[entity];
  const names = ["tenant_id", "source", "source_id", ...cols.map((c) => c[1]), "attributes", "connector_id", "run_id", "fetched_at"];
  const updates = names.slice(3).map((n) => `${n} = excluded.${n}`).join(", ");
  let written = 0;
  for (let i = 0; i < unique.length; i += BATCH) {
    const chunk = unique.slice(i, i + BATCH);
    const values: unknown[] = [];
    const rows = chunk.map((r) => {
      const row = [
        meta.tenant, meta.source, r.sourceId,
        ...cols.map(([f]) => r.fields[f] ?? null),
        JSON.stringify(r.attributes), meta.connectorId, meta.runId, meta.fetchedAt,
      ];
      const base = values.length;
      values.push(...row);
      return `(${row.map((_, j) => `$${base + j + 1}`).join(", ")})`;
    });
    const sql = `insert into ${ENTITY_TABLE[entity]} (${names.join(", ")}) values ${rows.join(", ")}
      on conflict (tenant_id, source, source_id) do update set ${updates}`;
    const res = await client.query(sql, values);
    written += res.rowCount ?? 0;
  }
  return written;
}
