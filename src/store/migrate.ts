// Applies migrations/*.sql in order using an admin URL, then sets role passwords
// from DATABASE_URL_APP / DATABASE_URL_BROKER. Never prints passwords.
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import pg from "pg";
import { loadBrokerEnv } from "../envfiles.ts";
import { startBoss } from "../scheduler/queue.ts";

const MIGRATIONS_DIR = join(import.meta.dirname, "../../migrations");

export async function migrate(
  adminUrl: string,
  rolePasswords: { app?: string; broker?: string } = {},
  say: (msg: string) => void = () => {},
  appUrl?: string,
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
    if (appUrl) await installQueue(client, appUrl, say);
  } finally {
    await client.end();
  }
}

/**
 * Install the pg-boss job-queue schema as ix_app, so ix_app owns its queue tables. pg-boss issues
 * CREATE SCHEMA on first install, which needs database-level CREATE; ix_app gets it only for the
 * duration of the install. At runtime pg-boss only checks its version, so the grant isn't needed.
 */
async function installQueue(admin: pg.Client, appUrl: string, say: (msg: string) => void): Promise<void> {
  const db = (await admin.query("select current_database() as d")).rows[0].d as string;
  const ident = admin.escapeIdentifier(db);
  await admin.query(`grant create on database ${ident} to ix_app`);
  try {
    const boss = await startBoss(appUrl);
    await boss.stop({ graceful: false });
    say("job queue schema ready");
  } finally {
    await admin.query(`revoke create on database ${ident} from ix_app`);
  }
}

export function passwordFromUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  return decodeURIComponent(new URL(url).password) || undefined;
}

async function main(): Promise<void> {
  loadBrokerEnv();
  const admin = process.env.DATABASE_URL_ADMIN;
  if (!admin) throw new Error("DATABASE_URL_ADMIN is not set (see .env.broker.example)");
  await migrate(
    admin,
    { app: passwordFromUrl(process.env.DATABASE_URL_APP), broker: passwordFromUrl(process.env.DATABASE_URL_BROKER) },
    (m) => console.log(m),
    process.env.DATABASE_URL_APP,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((err) => {
    console.error((err as Error).message);
    process.exit(1);
  });
}
