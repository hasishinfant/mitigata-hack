#!/usr/bin/env node
// ix CLI. Phase 7: validate, schema, add, update, run, runs, query, quarantine.
// `run` uses the in-process broker for now; Phase 5/6 route it through the API and broker process.
import { readFile } from "node:fs/promises";
import { Command } from "commander";
import { connectorJsonSchema } from "../config/schema.ts";
import { validateConfigText, type Issue } from "../config/validate.ts";
import { createRemoteBroker, type RemoteBroker } from "../broker/remote.ts";
import { verifyLedger } from "../broker/ledger.ts";
import { loadAdminEnv } from "../envfiles.ts";
import { runConnector } from "../engine/runner.ts";
import { testConnection, type ConnectionTest } from "../engine/testConnection.ts";
import { createPool, type Pool } from "../store/db.ts";
import { ConnectorConfigError, loadActiveConnector, setConnectorEnabled } from "../store/connectors.ts";
import { panic } from "../security/panic.ts";
import { getPosture, type Level } from "../security/posture.ts";
import { runRehearsal } from "../security/rehearsal.ts";
import { startBoss } from "../scheduler/queue.ts";
import { ENTITY_ALIASES, queryRecords } from "../store/query.ts";
import { listQuarantine } from "../store/quarantine.ts";
import { createPgRunStore, listRuns } from "../store/runs.ts";

// The CLI holds no provider secrets: it loads .env plus the broker admin token (.env.admin)
// and talks to the broker process over its sockets.
loadAdminEnv();

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
    .option("--confirm-hosts", "allow this config to send an already-stored secret to a host no approved config sends it to")
    .action(
      action(async (file: string, opts: { confirmHosts?: boolean }) => {
        const text = await readFile(file, "utf8");
        const r = await broker().register(text, name, process.env.USER ?? "cli", { confirmHosts: opts.confirmHosts === true });
        console.log(r.changed ? `${green("✔")} ${r.id} v${r.version} registered` : `${dim("=")} ${r.id} unchanged (v${r.version})`);
        if (r.newHosts?.length) console.log(yellow(`  existing secrets are now also sent to: ${r.newHosts.join(", ")}`));
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


const LEVEL_PAINT: Record<Level, (s: string) => string> = { high: red, medium: yellow, low: dim };

program
  .command("posture")
  .description("blast-radius card: what this connector can reach and what its credential could do if stolen")
  .argument("<id>")
  .option("--json")
  .action(
    action(async (id: string, opts: { json?: boolean }) => {
      const p = await getPosture(db(), id);
      if (opts.json) return console.log(JSON.stringify(p, null, 2));
      const badge = LEVEL_PAINT[p.risk](`${p.risk.toUpperCase()} RISK`);
      console.log(`${p.connector_id}  (${p.source}, ${p.auth_type}, ${p.status})  ${badge}`);
      console.log(dim("  reach"));
      for (const st of p.streams) {
        console.log(`    ${st.method} ${st.path}  -> ${st.entity}`);
        for (const f of st.fields) console.log(`      ${f.name}${f.sources.length ? ` <- ${f.sources.join(", ")}` : ""}`);
      }
      console.log(`    hosts: ${p.reach.allowed_hosts.join(", ")}`);
      console.log(`    paths: ${p.reach.allowed_paths.join(", ")}${p.reach.read_only_post.length ? `  read-only POST: ${p.reach.read_only_post.join(", ")}` : ""}`);
      console.log(`    methods: ${p.reach.methods.join(", ")}`);
      console.log(`    caps:  ${p.reach.max_requests_per_run} requests, ${p.reach.max_records_per_run} records per run`);
      console.log(dim("  credential"));
      for (const c of p.credentials)
        console.log(`    ${c.ref}: ${c.stored ? `age ${c.age_days}d, idle ${c.idle_days}d` : red("not stored")}${p.limits.max_age_days ? dim(`  (max age ${p.limits.max_age_days}d, idle limit ${p.limits.idle_disable_days ?? "-"}d)`) : ""}`);
      const sc = p.scopes;
      console.log(`    expected scopes: ${sc.expected.join(" ") || "-"}`);
      console.log(`    granted scopes:  ${sc.granted ? sc.granted.map((g) => (sc.forbidden.includes(g) || sc.writeLike.includes(g) ? red(g) : sc.extra.includes(g) ? yellow(g) : g)).join(" ") : dim("not reported by provider")}${sc.granted ? dim(` (${sc.source})`) : ""}`);
      console.log(`    revocable by API: ${p.revocable_by_api}   provider IP restriction: ${p.provider_ip_restriction}`);
      if (p.revoke_hint) console.log(`    revoke at: ${p.revoke_hint}`);
      console.log(`  policy violations (7d): ${p.violations_7d}${p.last_violation ? dim(`  last: ${String(p.last_violation.ts).slice(0, 19)} ${p.last_violation.decision}`) : ""}`);
      if (p.flags.length) {
        console.log(dim("  flags"));
        for (const f of p.flags) console.log(`    ${LEVEL_PAINT[f.level](f.level.padEnd(6))} ${f.message}`);
      }
    }),
  );

program
  .command("rm")
  .description("remove a connector, every record it stored, and its secrets (unless another connector uses them)")
  .argument("<id>")
  .option("--yes", "do not ask for confirmation")
  .option("--keep-secrets", "keep the connector's secrets in the broker")
  .action(
    action(async (id: string, opts: { yes?: boolean; keepSecrets?: boolean }) => {
      if (!opts.yes) {
        if (!process.stdin.isTTY) throw new Error("refusing to remove without --yes in a non-interactive shell");
        process.stderr.write(yellow(`remove ${id} and all its records? type the id to confirm: `));
        const answer = await new Promise<string>((resolve) => process.stdin.once("data", (d) => resolve(String(d).trim())));
        process.stdin.pause();
        if (answer !== id) throw new Error("cancelled");
      }
      const r = await broker().removeConnector(id, { purgeSecrets: !opts.keepSecrets });
      await db().query("delete from pgboss.job where data->>'connectorId' = $1 and state in ('created', 'retry')", [id]).catch(() => {});
      console.log(`${green("✔")} ${id} removed (${r.records} records deleted)`);
      if (r.secrets?.deleted.length) console.log(`  secrets deleted: ${r.secrets.deleted.join(", ")}`);
      if (r.secrets?.kept_shared.length) console.log(dim(`  secrets kept (still used by another connector): ${r.secrets.kept_shared.join(", ")}`));
    }),
  );

program
  .command("disable")
  .description("disable a connector and drop its cached token in the broker")
  .argument("<id>")
  .action(
    action(async (id: string) => {
      if (!(await setConnectorEnabled(db(), id, false, `disabled by ${process.env.USER ?? "operator"}`))) throw new Error(`connector ${id} not found`);
      await broker().forget(id).catch(() => console.log(yellow("  broker not reachable: its cached token expires on its own or on broker restart")));
      console.log(`${green("✔")} ${id} disabled`);
    }),
  );

program
  .command("enable")
  .description("re-enable a connector (restarts its idle clock)")
  .argument("<id>")
  .action(
    action(async (id: string) => {
      await broker().enableConnector(id); // through the broker: the app DB role cannot re-enable
      console.log(`${green("✔")} ${id} enabled`);
    }),
  );

program
  .command("panic")
  .description("kill switch: disable every connector, cancel queued runs, revoke/wipe tokens, print a revocation checklist")
  .option("--yes", "do not ask for confirmation")
  .option("--purge-secrets", "also delete every stored secret from the broker")
  .action(
    action(async (opts: { yes?: boolean; purgeSecrets?: boolean }) => {
      if (!opts.yes) {
        if (!process.stdin.isTTY) throw new Error("refusing to panic without --yes in a non-interactive shell");
        process.stderr.write(red("PANIC: disable ALL connectors and wipe tokens? type 'panic' to confirm: "));
        const answer = await new Promise<string>((resolve) => process.stdin.once("data", (d) => resolve(String(d).trim())));
        process.stdin.pause();
        if (answer !== "panic") throw new Error("cancelled");
      }
      const boss = await startBoss(process.env.DATABASE_URL_APP!).catch(() => undefined);
      const r = await panic(db(), { admin: broker(), boss, purgeSecrets: opts.purgeSecrets, actor: process.env.USER ?? "operator" });
      await boss?.stop({ graceful: false });
      console.log(red(`■ PANIC at ${r.at}`));
      console.log(`  connectors disabled: ${r.disabled.length}${r.disabled.length ? dim(` (${r.disabled.join(", ")})`) : ""}`);
      console.log(`  queued runs cancelled: ${r.queued_runs_cancelled}`);
      if (r.queued_runs_error) console.log(red(`  ${r.queued_runs_error}`));
      if (r.broker.error) console.log(red(`  ${r.broker.error}`));
      else console.log(`  broker: in-memory tokens wiped, ${r.broker.tokens_revoked} revoked at the provider, ${r.broker.secrets_purged} stored secrets purged`);
      console.log(dim("\n  revocation checklist"));
      for (const c of r.checklist) {
        const mark = c.action === "revoked_by_api" ? green("✔ revoked ") : c.action === "nothing_to_revoke" ? dim("- none    ") : red("☐ TODO    ");
        console.log(`  ${mark} ${c.connector_id.padEnd(22)} ${c.detail}`);
      }
      console.log(dim("\n  Re-enable one at a time after rotating its credential: ix secret set <ref> && ix enable <id>"));
    }),
  );

program
  .command("rehearse")
  .description("run a non-destructive incident-response rehearsal; no connectors or secrets are changed")
  .option("--json", "machine-readable output")
  .action(
    action(async (opts: { json?: boolean }) => {
      const report = await runRehearsal({ pool: db(), broker: broker() });
      if (opts.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log(`Incident-response rehearsal  ${report.ready ? green("READY") : red("NOT READY")}`);
        console.log(dim(`  generated ${report.generated_at}; no changes were made`));
        for (const check of report.checks) {
          const color = check.status === "pass" ? green : check.status === "attention" ? yellow : check.status === "fail" ? red : dim;
          console.log(`  ${color(check.status.toUpperCase().padEnd(11))} ${check.name}: ${check.detail}`);
        }
        console.log(dim("\n  panic plan (not executed)"));
        console.log(`    disable: ${report.panic_plan.disable_connectors.join(", ") || "no enabled connectors"}`);
        console.log("    cancel queued runs and clear the broker's in-memory token cache");
        console.log("    stored secrets will not be purged");
        for (const c of report.connectors) {
          const method = c.revocation === "api_revocation_declared"
            ? "config declares OAuth API revocation (not exercised; only cached tokens are revoked)"
            : c.revocation === "manual_provider_revocation"
              ? `manual provider revocation${c.revoke_hint ? `: ${c.revoke_hint}` : ""}`
              : c.revocation === "nothing_to_revoke" ? "no credential" : `posture unavailable: ${c.error}`;
          console.log(`    ${c.id}: ${method}`);
          for (const flag of c.flags) console.log(`      ${yellow(flag)}`);
        }
        if (!report.ready) process.exitCode = 1;
      }
      if (opts.json && !report.ready) process.exitCode = 1;
    }),
  );

program
  .command("alerts")
  .description("recent alerts and their delivery status")
  .option("-n, --limit <n>", "rows", "20")
  .action(
    action(async (opts: { limit: string }) => {
      const rows = (await db().query("select id, connector_id, kind, message, created_at, delivered, channel from alerts order by id desc limit $1", [Number(opts.limit)])).rows;
      if (!rows.length) return console.log(dim("no alerts"));
      for (const a of rows.reverse())
        console.log(`#${String(a.id).padEnd(4)} ${String(a.created_at).slice(0, 19)}  ${(a.connector_id ?? "-").padEnd(20)} ${yellow(a.kind.padEnd(20))} ${a.message}${dim(`  [${a.delivered ? `sent:${a.channel}` : a.channel ?? "pending"}]`)}`);
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
