#!/usr/bin/env node
// ix CLI. Phase 6: validate, schema, add, update, run, runs, query, quarantine.
// `run` uses the in-process broker for now; Phase 5/6 route it through the API and broker process.
import { readFile } from "node:fs/promises";
import { Command } from "commander";
import { connectorJsonSchema } from "../config/schema.ts";
import { validateConfigText, type Issue } from "../config/validate.ts";
import { createRemoteBroker, type RemoteBroker } from "../broker/remote.ts";
import { verifyLedger } from "../broker/ledger.ts";
import { loadAppEnv } from "../envfiles.ts";
import { runConnector } from "../engine/runner.ts";
import { testConnection, type ConnectionTest } from "../engine/testConnection.ts";
import { createPool, type Pool } from "../store/db.ts";
import { ConnectorConfigError, loadActiveConnector } from "../store/connectors.ts";
import { ENTITY_ALIASES, queryRecords } from "../store/query.ts";
import { listQuarantine } from "../store/quarantine.ts";
import { createPgRunStore, listRuns } from "../store/runs.ts";

// The CLI holds no secrets: it loads only .env and talks to the broker process over its socket.
loadAppEnv();

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
let rb: RemoteBroker | undefined;
const db = () => (pool ??= createPool(process.env.DATABASE_URL_APP));
const broker = () => (rb ??= createRemoteBroker());

/** Read a secret without echoing it: hidden prompt on a TTY, otherwise all of stdin (for PEM files). */
async function readSecretInput(ref: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
  }
  process.stderr.write(`value for ${ref} (input hidden): `);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let value = "";
    const onData = (buf: Buffer) => {
      for (const ch of buf.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          done();
          return resolve(value);
        }
        if (ch === "\u0003") {
          done();
          return reject(new Error("cancelled"));
        }
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    };
    const done = () => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stderr.write("\n");
    };
    process.stdin.on("data", onData);
  });
}

/** Wrap a command: friendly errors, always close the pool. */
function action<A extends unknown[]>(fn: (...args: A) => Promise<void>) {
  return async (...args: A) => {
    try {
      await fn(...args);
    } catch (e) {
      const issues = e instanceof ConnectorConfigError ? e.issues : (e as { issues?: Issue[] }).issues;
      console.error(red(`✖ ${(e as Error).message}`));
      if (Array.isArray(issues)) issues.forEach((i) => console.error(`  ${i.line}:${i.col}  ${i.path}: ${i.message}`));
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

for (const [name, desc] of [
  ["add", "register a new connector from a config file (the broker validates and signs it)"],
  ["update", "store a new version of an existing connector (re-signed by the broker)"],
] as const) {
  program
    .command(name)
    .description(desc)
    .argument("<file>")
    .action(
      action(async (file: string) => {
        const text = await readFile(file, "utf8");
        const r = await broker().register(text, name, process.env.USER ?? "cli");
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
      const results = await runConnector({ connector: conn, broker: broker(), store: createPgRunStore(db()), streams: opts.stream });
      for (const r of results) {
        console.log(
          `${r.stream.padEnd(12)} ${paint(r.status).padEnd(tty ? 21 : 12)} requests=${r.requests} ok=${r.recordsOk} quarantined=${r.recordsQuarantined}` +
            (r.retries ? ` retries=${r.retries}` : "") +
            (r.rateLimitedMs ? ` waited=${(r.rateLimitedMs / 1000).toFixed(1)}s` : "") +
            (r.resumed ? yellow(" (resumed from checkpoint)") : "") +
            (r.lastError ? dim(`  ${r.lastError}`) : ""),
        );
      }
      if (results.some((r) => !["success", "partial", "paused"].includes(r.status))) process.exitCode = 1;
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
            (r.retries ? ` retries=${r.retries}` : "") +
            (r.rate_limited_ms ? ` waited=${(r.rate_limited_ms / 1000).toFixed(1)}s` : "") +
            (r.resumed ? " resumed" : "") +
            (r.last_error ? dim(`  ${r.last_error}`) : ""),
        );
    }),
  );

const secret = program.command("secret").description("manage encrypted credentials (values are write-only)");
secret
  .command("set")
  .description("store a secret; reads a hidden prompt, or stdin when piped (e.g. < key.pem)")
  .argument("<ref>")
  .option("-t, --tenant <tenant>", "tenant", "demo")
  .action(
    action(async (ref: string, opts: { tenant: string }) => {
      if (!/^[a-z][a-z0-9_]{1,63}$/.test(ref)) throw new Error("ref: lowercase letters, digits, _ (e.g. github_pat)");
      const value = await readSecretInput(ref);
      if (!value) throw new Error("empty value, nothing stored");
      await broker().putSecret(opts.tenant, ref, value);
      console.log(`${green("✔")} ${opts.tenant}/${ref} stored encrypted (${value.length} chars)`);
    }),
  );
secret
  .command("list")
  .description("list secret refs with age and last use (never values)")
  .option("-t, --tenant <tenant>")
  .action(
    action(async (opts: { tenant?: string }) => {
      const rows = await broker().listSecrets(opts.tenant);
      if (!rows.length) return console.log(dim("no secrets stored"));
      for (const r of rows)
        console.log(`${r.tenant_id}/${r.ref}`.padEnd(32) + ` age=${r.age_days}d  last_used=${r.last_used_at ? String(r.last_used_at).slice(0, 19) : "never"}`);
    }),
  );
secret
  .command("rm")
  .description("delete a secret")
  .argument("<ref>")
  .option("-t, --tenant <tenant>", "tenant", "demo")
  .action(
    action(async (ref: string, opts: { tenant: string }) => {
      const ok = await broker().deleteSecret(opts.tenant, ref);
      console.log(ok ? `${green("✔")} ${opts.tenant}/${ref} deleted` : dim(`${opts.tenant}/${ref} not found`));
    }),
  );

program
  .command("test")
  .description("test a connector (registered id or config file): auth + first page + 3 mapped records; writes nothing")
  .argument("<idOrFile>")
  .option("--raw", "show redacted raw sample records")
  .action(
    action(async (idOrFile: string, opts: { raw?: boolean }) => {
      let t: ConnectionTest;
      let expected: string[] | undefined;
      if (/\.ya?ml$/.test(idOrFile)) {
        // An unregistered file can only be tested if it uses no secrets (the broker enforces this too).
        const text = await readFile(idOrFile, "utf8");
        const res = validateConfigText(text);
        if (!res.ok || !res.config) throw new ConnectorConfigError(`${idOrFile} is invalid (run ix validate)`, res.errors);
        if (res.config.connection.auth.type !== "none")
          throw new Error(`${idOrFile} uses secrets: register it first (ix add ${idOrFile}), then run: ix test ${res.config.metadata.id}`);
        t = await broker().testInline(text);
      } else {
        const conn = await loadActiveConnector(db(), idOrFile);
        expected = conn.credential?.expected_scopes;
        t = await testConnection(conn, broker(), { showRaw: opts.raw });
      }
      console.log(`${t.ok ? green("✔") : red("✖")} ${t.connectorId}`);
      for (const s of t.streams) {
        console.log(`  stream ${s.stream}: ${s.status ? `HTTP ${s.status} in ${s.durationMs} ms, ` : ""}${s.recordsOnPage ?? 0} records on first page${s.hasMorePages ? ", more pages" : ""}`);
        if (s.error) console.log(red(`    ${s.error}`));
        if (s.warning) console.log(yellow(`    ${s.warning}`));
        for (const smp of s.samples) {
          if (smp.result.ok) console.log(dim(`    ✔ ${JSON.stringify({ id: smp.result.record.sourceId, ...smp.result.record.fields })}`));
          else console.log(yellow(`    ✖ ${smp.result.errors.join("; ")}`));
          if (smp.raw) console.log(dim(`      raw: ${JSON.stringify(smp.raw).slice(0, 300)}`));
        }
      }
      if (t.credential.grantedScopes) {
        console.log(`  granted scopes (${t.credential.scopeSource}): ${t.credential.grantedScopes.join(" ") || "(none)"}`);
        const extra = t.credential.grantedScopes.filter((x) => expected && !expected.includes(x));
        if (extra.length) console.log(yellow(`  more than expected: ${extra.join(" ")}`));
      } else console.log(dim("  granted scopes: provider did not report them"));
      if (!t.ok) process.exitCode = 1;
    }),
  );

const audit = program.command("audit").description("hash-chained audit ledger of every outbound call, denial and secret change");
audit
  .command("verify")
  .description("recompute the hash chain; detects edited, deleted or reordered rows")
  .action(
    action(async () => {
      const r = await verifyLedger(db());
      if (r.ok) console.log(`${green("✔")} ledger intact: ${r.rows} rows, hash chain verified`);
      else {
        console.log(red(`✖ ledger tampered: ${r.problem}`));
        process.exitCode = 1;
      }
    }),
  );
audit
  .command("log")
  .description("recent ledger entries")
  .option("-n, --limit <n>", "rows", "20")
  .option("--deny", "only denied requests")
  .action(
    action(async (opts: { limit: string; deny?: boolean }) => {
      const rows = (
        await db().query(
          `select seq, ts, connector_id, action, method, host, path, status, decision from audit_ledger
           where ($1::boolean is not true or decision like 'deny%') order by seq desc limit $2`,
          [opts.deny ?? false, Number(opts.limit)],
        )
      ).rows;
      for (const r of rows.reverse()) {
        const d = String(r.decision);
        const tag = d.startsWith("deny") ? red(d) : d.startsWith("error") ? yellow(d) : dim(d);
        console.log(`#${String(r.seq).padEnd(5)} ${String(r.ts).slice(0, 19)}  ${(r.connector_id ?? "-").padEnd(20)} ${r.action.padEnd(13)} ${(r.method ?? "").padEnd(5)} ${(r.host ?? "")}${r.path ?? ""} ${r.status ?? ""}  ${tag}`);
      }
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
