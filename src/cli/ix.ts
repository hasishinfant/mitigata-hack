#!/usr/bin/env node
// ix CLI. Phase 2: validate, schema, add, update, run, runs, query, quarantine.
// `run` uses the in-process broker for now; Phase 5/6 route it through the API and broker process.
import { readFile } from "node:fs/promises";
import { Command } from "commander";
import { connectorJsonSchema } from "../config/schema.ts";
import { validateConfigText, type Issue } from "../config/validate.ts";
import { createLocalBroker } from "../broker/client.ts";
import { envSecretSource } from "../broker/secrets.ts";
import { runConnector } from "../engine/runner.ts";
import { createPool, type Pool } from "../store/db.ts";
import { ConnectorConfigError, loadActiveConnector, registerConnector } from "../store/connectors.ts";
import { ENTITY_ALIASES, queryRecords } from "../store/query.ts";
import { listQuarantine } from "../store/quarantine.ts";
import { createPgRunStore, listRuns } from "../store/runs.ts";

try { process.loadEnvFile(); } catch { /* no .env is fine */ }

const tty = process.stdout.isTTY;
const c = (code: number, s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = (s: string) => c(31, s);
const yellow = (s: string) => c(33, s);
const green = (s: string) => c(32, s);
const dim = (s: string) => c(2, s);
const STATUS_COLOR: Record<string, (s: string) => string> = { success: green, partial: yellow, degraded: yellow, running: dim };
const paint = (status: string) => (STATUS_COLOR[status] ?? red)(status);

function printIssue(i: Issue, lines: string[]): void {
  const tag = i.severity === "error" ? red("error  ") : yellow("warning");
  console.log(`  ${`${i.line}:${i.col}`.padEnd(7)} ${tag}  ${i.path}: ${i.message}`);
  const src = lines[i.line - 1];
  if (src !== undefined && i.path !== "(root)") console.log(dim(`          | ${src.trimEnd()}`));
}

let pool: Pool | undefined;
const db = () => (pool ??= createPool(process.env.DATABASE_URL_APP));

/** Wrap a command: friendly errors, always close the pool. */
function action<A extends unknown[]>(fn: (...args: A) => Promise<void>) {
  return async (...args: A) => {
    try {
      await fn(...args);
    } catch (e) {
      if (e instanceof ConnectorConfigError) {
        console.error(red(`✖ ${e.message}`));
        e.issues.forEach((i) => console.error(`  ${i.line}:${i.col}  ${i.path}: ${i.message}`));
      } else console.error(red(`✖ ${(e as Error).message}`));
      process.exitCode = 1;
    } finally {
      await pool?.end();
    }
  };
}

const program = new Command().name("ix").description("IntegrateX: config-driven security integrations");

program
  .command("validate")
  .description("validate connector config file(s): line-numbered errors and policy warnings")
  .argument("<files...>")
  .option("--json", "machine-readable output")
  .action(async (files: string[], opts: { json?: boolean }) => {
    let failed = false;
    const out: Record<string, unknown> = {};
    for (const file of files) {
      let text: string;
      try {
        text = await readFile(file, "utf8");
      } catch (e) {
        console.error(red(`${file}: ${(e as Error).message}`));
        failed = true;
        continue;
      }
      const res = validateConfigText(text);
      failed ||= !res.ok;
      if (opts.json) {
        out[file] = { ok: res.ok, errors: res.errors, warnings: res.warnings, config_hash: res.configHash };
        continue;
      }
      const lines = text.split("\n");
      console.log(res.ok ? `${green("✔")} ${file}` : `${red("✖")} ${file}`);
      [...res.errors, ...res.warnings].forEach((i) => printIssue(i, lines));
      console.log(dim(`  ${res.errors.length} error(s), ${res.warnings.length} warning(s)\n`));
    }
    if (opts.json) console.log(JSON.stringify(out, null, 2));
    process.exitCode = failed ? 1 : 0;
  });

program
  .command("schema")
  .description("print the ix/v1 connector JSON Schema (for editor autocompletion)")
  .action(() => console.log(JSON.stringify(connectorJsonSchema(), null, 2)));

for (const [name, desc, flags] of [
  ["add", "register a new connector from a config file", { mustNotExist: true }],
  ["update", "store a new version of an existing connector", { mustExist: true }],
] as const) {
  program
    .command(name)
    .description(desc)
    .argument("<file>")
    .action(
      action(async (file: string) => {
        const text = await readFile(file, "utf8");
        const r = await registerConnector(db(), text, { ...flags, createdBy: process.env.USER ?? "cli" });
        console.log(r.changed ? `${green("✔")} ${r.id} v${r.version} registered` : `${dim("=")} ${r.id} unchanged (v${r.version})`);
      }),
    );
}

program
  .command("run")
  .description("sync a connector now")
  .argument("<id>")
  .option("-s, --stream <name...>", "only these streams")
  .action(
    action(async (id: string, opts: { stream?: string[] }) => {
      const conn = await loadActiveConnector(db(), id);
      if (conn.status !== "enabled") throw new Error(`connector ${id} is ${conn.status}`);
      const broker = createLocalBroker({ getConnector: (cid) => (cid === conn.metadata.id ? conn : undefined), secrets: envSecretSource() });
      const results = await runConnector({ connector: conn, broker, store: createPgRunStore(db()), streams: opts.stream });
      for (const r of results) {
        console.log(
          `${r.stream.padEnd(12)} ${paint(r.status).padEnd(tty ? 21 : 12)} requests=${r.requests} ok=${r.recordsOk} quarantined=${r.recordsQuarantined}` +
            (r.lastError ? dim(`  ${r.lastError}`) : ""),
        );
      }
      if (results.some((r) => !["success", "partial"].includes(r.status))) process.exitCode = 1;
    }),
  );

program
  .command("runs")
  .description("run history for a connector")
  .argument("<id>")
  .option("-n, --limit <n>", "rows", "20")
  .action(
    action(async (id: string, opts: { limit: string }) => {
      const rows = await listRuns(db(), id, Number(opts.limit));
      if (!rows.length) return console.log(dim("no runs yet"));
      for (const r of rows)
        console.log(
          `${String(r.started_at).slice(0, 19)}  ${r.stream.padEnd(10)} ${paint(r.status).padEnd(tty ? 21 : 12)} req=${r.requests} ok=${r.records_ok} q=${r.records_quarantined}` +
            (r.last_error ? dim(`  ${r.last_error}`) : ""),
        );
    }),
  );

program
  .command("query")
  .description("query the common store: users | devices | events")
  .argument("<entity>")
  .option("--source <source>")
  .option("--since <iso>", "fetched at or after")
  .option("--type <type>", "event type")
  .option("-n, --limit <n>", "rows", "20")
  .option("--json")
  .action(
    action(async (entityArg: string, opts: { source?: string; since?: string; type?: string; limit: string; json?: boolean }) => {
      const entity = ENTITY_ALIASES[entityArg];
      if (!entity) throw new Error(`unknown entity "${entityArg}" (users, devices, events)`);
      const { total, rows } = await queryRecords(db(), entity, { ...opts, limit: Number(opts.limit) });
      if (opts.json) return console.log(JSON.stringify({ total, rows }, null, 2));
      if (rows.length) console.table(rows.map(({ fetched_at: _f, ...r }) => r));
      console.log(dim(`${rows.length} of ${total} ${entityArg}`));
    }),
  );

program
  .command("quarantine")
  .description("records that failed mapping, with reasons")
  .option("-c, --connector <id>")
  .option("-n, --limit <n>", "rows", "20")
  .option("--raw", "include redacted raw payload")
  .action(
    action(async (opts: { connector?: string; limit: string; raw?: boolean }) => {
      const rows = await listQuarantine(db(), { connectorId: opts.connector, limit: Number(opts.limit) });
      if (!rows.length) return console.log(dim("quarantine is empty"));
      for (const r of rows) {
        console.log(`#${r.id}  ${r.connector_id}  ${String(r.created_at).slice(0, 19)}  ${red((r.errors as string[]).join("; "))}`);
        if (opts.raw) console.log(dim(`    ${JSON.stringify(r.raw_redacted).slice(0, 400)}`));
      }
    }),
  );

await program.parseAsync();
