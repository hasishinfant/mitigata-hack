// Applies migrations/*.sql in order using an admin URL, then sets role passwords
// from DATABASE_URL_APP / DATABASE_URL_BROKER. Never prints passwords.
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import pg from "pg";

const MIGRATIONS_DIR = join(import.meta.dirname, "../../migrations");

export async function migrate(
  adminUrl: string,
  rolePasswords: { app?: string; broker?: string } = {},
  say: (msg: string) => void = () => {},
): Promise<void> {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    await client.query("create table if not exists schema_migrations (name text primary key, applied_at timestamptz default now())");
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
        say(`applied ${file}`);
      } catch (err) {
        await client.query("rollback");
        throw new Error(`migration ${file} failed: ${(err as Error).message}`);
      }
    }
    for (const [role, password] of [["ix_app", rolePasswords.app], ["ix_broker", rolePasswords.broker]] as const) {
      if (!password) continue;
      await client.query(`alter role ${role} password ${client.escapeLiteral(password)}`);
      say(`set password for ${role}`);
    }
  } finally {
    await client.end();
  }
}

export function passwordFromUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  return decodeURIComponent(new URL(url).password) || undefined;
}

async function main(): Promise<void> {
  try { process.loadEnvFile(); } catch { /* no .env is fine */ }
  const admin = process.env.DATABASE_URL_ADMIN;
  if (!admin) throw new Error("DATABASE_URL_ADMIN is not set (see .env.example)");
  await migrate(
    admin,
    { app: passwordFromUrl(process.env.DATABASE_URL_APP), broker: passwordFromUrl(process.env.DATABASE_URL_BROKER) },
    (m) => console.log(m),
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((err) => {
    console.error((err as Error).message);
    process.exit(1);
  });
}
