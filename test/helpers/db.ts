// Tests run against a separate database (integratex_test) so demo data is never touched.
import { createPool, type Pool } from "../../src/store/db.ts";

for (const f of [".env", ".env.broker"]) {
  try {
    process.loadEnvFile(f);
  } catch {
    /* CI may set env directly */
  }
}

export const TEST_DB = "integratex_test";
export const hasDb = Boolean(process.env.DATABASE_URL_ADMIN && process.env.DATABASE_URL_APP && process.env.DATABASE_URL_BROKER);

export function testUrl(name: "DATABASE_URL_ADMIN" | "DATABASE_URL_APP" | "DATABASE_URL_BROKER", db = TEST_DB): string {
  const raw = process.env[name];
  if (!raw) throw new Error(`${name} not set`);
  const u = new URL(raw);
  u.pathname = `/${db}`;
  return u.href;
}

// Config versions, connectors and tenants are broker-only writes since Phase 6.
let reg: Pool | undefined;
export const regPool = (): Pool => (reg ??= createPool(testUrl("DATABASE_URL_BROKER")));
export async function closeRegPool(): Promise<void> {
  await reg?.end();
  reg = undefined;
}

export async function clearData(pool: Pool): Promise<void> {
  for (const t of ["quarantine", "runs", "checkpoints", "users", "devices", "events", "alerts"]) await pool.query(`delete from ${t}`);
  for (const t of ["credentials", "connector_versions", "connectors", "tenants"]) await regPool().query(`delete from ${t}`);
}
