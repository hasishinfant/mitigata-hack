// Tests run against a separate database (integratex_test) so demo data is never touched.
import type { Pool } from "../../src/store/db.ts";

try { process.loadEnvFile(); } catch { /* CI may set env directly */ }

export const TEST_DB = "integratex_test";
export const hasDb = Boolean(process.env.DATABASE_URL_ADMIN && process.env.DATABASE_URL_APP);

export function testUrl(name: "DATABASE_URL_ADMIN" | "DATABASE_URL_APP" | "DATABASE_URL_BROKER", db = TEST_DB): string {
  const raw = process.env[name];
  if (!raw) throw new Error(`${name} not set`);
  const u = new URL(raw);
  u.pathname = `/${db}`;
  return u.href;
}

export async function clearData(pool: Pool): Promise<void> {
  for (const t of ["quarantine", "runs", "checkpoints", "users", "devices", "events", "alerts", "connector_versions", "connectors", "tenants"])
    await pool.query(`delete from ${t}`);
}
