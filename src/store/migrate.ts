// Applies migrations/*.sql in order using DATABASE_URL_ADMIN, then sets role passwords
// from DATABASE_URL_APP / DATABASE_URL_BROKER. Never prints passwords.
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import pg from "pg";

try { process.loadEnvFile(); } catch { /* no .env is fine */ }

const MIGRATIONS_DIR = join(import.meta.dirname, "../../migrations");

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set (see .env.example)`);
  return v;
}

async function main(): Promise<void> {
  const client = new pg.Client({ connectionString: requireEnv("DATABASE_URL_ADMIN") });
  await client.connect();
  try {
    await client.query(
      "create table if not exists schema_migrations (name text primary key, applied_at timestamptz default now())",
    );
    const done = new Set((await client.query("select name from schema_migrations")).rows.map((r) => r.name));
    const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith(".sql")).sort();
    for (const file of files) {
      if (done.has(file)) continue;
      const sql = await readFile(join(MIGRATIONS_DIR, file), "utf8");
      await client.query("begin");
      try {
        await client.query(sql);
        await client.query("insert into schema_migrations (name) values ($1)", [file]);
        await client.query("commit");
        console.log(`applied ${file}`);
      } catch (err) {
        await client.query("rollback");
        throw new Error(`migration ${file} failed: ${(err as Error).message}`);
      }
    }
    for (const [envName, role] of [["DATABASE_URL_APP", "ix_app"], ["DATABASE_URL_BROKER", "ix_broker"]] as const) {
      const url = process.env[envName];
      if (!url) continue;
      const password = decodeURIComponent(new URL(url).password);
      if (!password) continue;
      await client.query(`alter role ${role} password ${client.escapeLiteral(password)}`);
      console.log(`set password for ${role}`);
    }
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error((err as Error).message);
  process.exit(1);
});
