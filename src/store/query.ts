// Read the common-schema tables (FR-11).
import type pg from "pg";
import type { Entity } from "../config/schema.ts";
import { ENTITY_TABLE } from "./upsert.ts";

export const ENTITY_ALIASES: Record<string, Entity> = { user: "user", users: "user", device: "device", devices: "device", event: "event", events: "event" };

const SELECT: Record<Entity, string> = {
  user: "source_id as id, name, email, status, source, last_login, fetched_at",
  device: "source_id as id, hostname, host(ip) as ip, os, owner, source, last_seen, fetched_at",
  event: "source_id as id, type, severity, ts as timestamp, description, source, fetched_at",
};

export async function queryRecords(
  pool: pg.Pool,
  entity: Entity,
  opts: { tenant?: string; source?: string; since?: string; type?: string; search?: string; limit?: number; offset?: number; withAttributes?: boolean } = {},
): Promise<{ total: number; rows: Record<string, unknown>[] }> {
  const where: string[] = [];
  const params: unknown[] = [];
  const add = (sql: string, v: unknown) => {
    params.push(v);
    where.push(sql.replace("?", `$${params.length}`));
  };
  if (opts.tenant) add("tenant_id = ?", opts.tenant);
  if (opts.source) add("source = ?", opts.source);
  if (opts.since) add("fetched_at >= ?::timestamptz", opts.since);
  if (opts.type && entity === "event") add("type = ?", opts.type);
  // Free-text search over every column of the row, attributes included (case-insensitive substring).
  if (opts.search) add("r::text ilike ?", `%${opts.search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
  const w = where.length ? `where ${where.join(" and ")}` : "";
  const table = ENTITY_TABLE[entity];
  const total = Number((await pool.query(`select count(*) from ${table} r ${w}`, params)).rows[0].count);
  const order = entity === "event" ? "ts desc nulls last" : "source, source_id";
  const cols = SELECT[entity] + (opts.withAttributes ? ", attributes" : "");
  const rows = (
    await pool.query(`select ${cols} from ${table} r ${w} order by ${order} limit ${Math.min(opts.limit ?? 50, 1000)} offset ${opts.offset ?? 0}`, params)
  ).rows;
  return { total, rows };
}
