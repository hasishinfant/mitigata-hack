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
import { ConnectorBusy, runConnector } from "../engine/runner.ts";
import { testConnection, type ConnectionTest } from "../engine/testConnection.ts";
import { createPool, type Pool } from "../store/db.ts";
import { ConnectorConfigError, loadActiveConnector, setConnectorEnabled } from "../store/connectors.ts";
import { panic } from "../security/panic.ts";
import { getPosture, type Level } from "../security/posture.ts";
import { capabilityMatrix } from "../security/capabilities.ts";
import { closeIncident, declareIncident, incidentState } from "../security/incident.ts";
import { advise } from "../security/advisor.ts";
import { runRehearsal } from "../security/rehearsal.ts";
import { enqueueRun, startBoss } from "../scheduler/queue.ts";
import { ENTITY_ALIASES, queryRecords } from "../store/query.ts";
import { listQuarantine } from "../store/quarantine.ts";
import { createPgRunStore, listRuns } from "../store/runs.ts";
import { listHeld, listReceipts, resolveHeldSync, verifyReceipt } from "../store/staging.ts";

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
const DECISION_COLOR: Record<string, (s: string) => string> = {
  verified: green, verified_empty: green, approved: green, held: yellow, incomplete: dim, rejected: red, discarded: dim,
};

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
  .description("sync a connector now: queued for the worker (same path as scheduled runs), waits for the result")
  .argument("<id>")
  .option("-s, --stream <name...>", "only these streams (runs here, like --local)")
  .option("--local", "run in this process instead of through the job queue (still single-flight per connector)")
  .action(
    action(async (id: string, opts: { stream?: string[]; local?: boolean }) => {
      const conn = await loadActiveConnector(db(), id);
      if (!opts.local && !opts.stream) return runQueued(conn.metadata.id, conn.streams.length);
      let results;
      try {
        results = await runConnector({ connector: conn, broker: broker(), store: createPgRunStore(db()), streams: opts.stream });
      } catch (e) {
        if (!(e instanceof ConnectorBusy)) throw e;
        console.log(yellow(`⏳ ${e.message}`));
        process.exitCode = 2;
        return;
      }
      for (const r of results) {
        console.log(
          `${r.stream.padEnd(12)} ${paint(r.status).padEnd(tty ? 21 : 12)} requests=${r.requests} ok=${r.recordsOk} quarantined=${r.recordsQuarantined}` +
            (r.retries ? ` retries=${r.retries}` : "") +
            (r.rateLimitedMs ? ` waited=${(r.rateLimitedMs / 1000).toFixed(1)}s` : "") +
            (r.resumed ? yellow(" (resumed from checkpoint)") : "") +
            (r.lastError ? dim(`  ${r.lastError}`) : ""),
        );
        if (r.decision)
          console.log(
            `${"".padEnd(13)}${DECISION_COLOR[r.decision]?.(r.decision) ?? r.decision}` +
              (r.published !== undefined ? ` · published ${r.published}` : "") +
              (r.receiptId ? dim(` · receipt #${r.receiptId} sha256:${r.receiptDigest?.slice(0, 12)}…`) : "") +
              (r.decision === "held" ? yellow(`  → review: ix held · ix approve ${r.syncId} · ix discard ${r.syncId}`) : ""),
          );
      }
      if (results.some((r) => !["success", "partial", "paused"].includes(r.status))) process.exitCode = 1;
    }),
  );

const canary = program.command("canary").description("decoy credentials: stored like real secrets; any use raises a critical alert");
canary
  .command("create")
  .description("create a decoy secret (never replaces a real one)")
  .argument("<ref>", "a believable name, e.g. okta_admin_token, aws_root_key, slack_webhook_prod")
  .option("--url", "a webhook-style URL decoy that points at the hub's canary listener (detects use outside the hub)")
  .option("--prefix <p>", "token prefix to look real, e.g. ghp_ or sk_live_", "")
  .option("-t, --tenant <tenant>", "tenant", "demo")
  .option("--print", "print the decoy value, to plant copies (fake .env files, tickets, docs)")
  .action(
    action(async (ref: string, opts: { url?: boolean; prefix: string; tenant: string; print?: boolean }) => {
      const r = await broker().createCanary({ tenant: opts.tenant, ref, kind: opts.url ? "url" : "key", prefix: opts.prefix });
      console.log(`${green("✔")} decoy ${r.tenant}/${r.ref} (${r.kind}) stored encrypted, indistinguishable from a real secret`);
      if (opts.print) console.log(r.value);
      else console.log(dim("  use --print to get the value to plant elsewhere"));
    }),
  );
canary
  .command("list")
  .description("which stored secrets are decoys (only the broker can tell)")
  .option("-t, --tenant <tenant>", "tenant")
  .action(
    action(async (opts: { tenant?: string }) => {
      const rows = await broker().listCanaries(opts.tenant);
      if (!rows.length) return console.log(dim("no decoys"));
      for (const c of rows) console.log(`${c.tenant}/${c.ref}  ${c.kind}  ${String(c.created_at).slice(0, 19)}`);
    }),
  );

program
  .command("capabilities")
  .description("capability registry: each security control per connector (enforced / available / monitored / unsupported / n/a)")
  .option("-v, --verbose", "show the detail for each cell")
  .action(
    action(async (opts: { verbose?: boolean }) => {
      const ids = (await db().query("select id from connectors order by id")).rows.map((r) => r.id as string);
      const m = await capabilityMatrix(ids, (id) => loadActiveConnector(db(), id));
      const sym: Record<string, (s: string) => string> = {
        enforced: (s) => green(s), monitored: (s) => green(s), available: (s) => yellow(s), unknown: (s) => yellow(s), unsupported: (s) => dim(s), not_applicable: (s) => dim(s),
      };
      const short: Record<string, string> = { enforced: "ENFORCED", monitored: "monitored", available: "AVAILABLE", unknown: "unknown", unsupported: "unsupported", not_applicable: "n/a" };
      const w = 12;
      console.log("".padEnd(20) + m.controls.map((c) => c.slice(0, w - 1).padEnd(w)).join(""));
      for (const c of m.connectors) {
        if (!c.capabilities) {
          console.log(`${c.id.padEnd(20)}${red(c.error ?? "unreadable")}`);
          continue;
        }
        console.log(c.id.padEnd(20) + m.controls.map((k) => sym[c.capabilities![k].status]!(short[c.capabilities![k].status]!.padEnd(w))).join(""));
        if (opts.verbose) for (const k of m.controls) console.log(dim(`    ${k}: ${c.capabilities[k].detail}`));
      }
      console.log(dim("AVAILABLE = the provider supports it but it isn't enabled; unknown = declare it under capabilities: in the config"));
    }),
  );

const incident = program.command("incident").description("incident mode: connectors with schedule.incident_every poll faster");
incident
  .command("start")
  .argument("[reason...]")
  .description("declare an incident (also starts automatically on a canary or foreign-IP alert)")
  .action(action(async (reason: string[]) => {
    await declareIncident(db(), reason.join(" ") || "declared by an operator", process.env.USER ?? "cli");
    const s = await incidentState(db());
    console.log(`${yellow("⚡ incident mode on")} until ${s.until} (extends with every new security alert)`);
  }));
incident.command("stop").description("end incident mode").action(action(async () => {
  await closeIncident(db(), process.env.USER ?? "cli");
  console.log(`${green("✔")} incident mode off: normal schedules`);
}));
incident.command("status").description("is incident mode on, and why").action(action(async () => {
  const s = await incidentState(db());
  if (!s.active) return console.log(dim("no active incident"));
  console.log(`${yellow("⚡ incident mode on")} since ${s.since}, until ${s.until}\n  ${s.reason}`);
  const fast = (await db().query("select id from connectors where status <> 'disabled' order by id")).rows.map((r) => r.id as string);
  for (const id of fast) {
    const c = await loadActiveConnector(db(), id).catch(() => null);
    if (c?.schedule?.incident_every) console.log(`  ${id}: every ${c.schedule.incident_every} (normally ${c.schedule.every})`);
  }
}));

program
  .command("advise")
  .description("incident advisor: rule-based findings and kill-switch recommendation, explained by Claude (claims cite evidence)")
  .option("--no-ai", "rules only, no Claude call")
  .option("--hours <n>", "look back this many hours", "24")
  .action(
    action(async (opts: { ai: boolean; hours: string }) => {
      const r = await advise(db(), { ai: opts.ai, windowHours: Number(opts.hours), narrate: (a) => broker().narrate(a) });
      const rec = { kill_switch: red("KILL SWITCH RECOMMENDED"), investigate: yellow("investigate"), monitor: dim("monitor"), all_clear: green("all clear") }[r.recommendation];
      console.log(`${rec}  (rules, last ${r.window_hours} h)`);
      for (const x of r.reasons) console.log(`  · ${x}`);
      for (const f of r.findings) console.log(`  ${f.severity.toUpperCase().padEnd(8)} ${f.scope}: ${f.title}  ${dim(f.evidence.join(" "))}`);
      if (r.ai.used && r.ai.narrative) {
        console.log(`\n${r.ai.narrative.headline}  ${dim(`(${r.ai.model}; ${r.ai.kept} claims kept, ${r.ai.dropped} dropped for citing unknown evidence)`)}`);
        for (const i of r.ai.narrative.incidents) {
          console.log(`  ${i.scope}: ${i.summary}`);
          for (const c of i.claims) console.log(`    - ${c.text} ${dim(`[${c.evidence_ids.join(", ")}]`)}`);
          for (const s of i.next_steps) console.log(`    → ${s}`);
        }
      } else console.log(dim(`\nAI: ${r.ai.note ?? "not used"}`));
      if (r.recommendation === "kill_switch") console.log(red("\nIf this is confirmed: ix panic --yes (or the dashboard's Kill switch). The advisor never presses it."));
    }),
  );

program
  .command("receipts")
  .description("Sync Integrity Receipts for a connector: decision, what was published, digest and ledger anchor")
  .argument("<id>")
  .option("-n, --limit <n>", "rows", "20")
  .action(
    action(async (id: string, opts: { limit: string }) => {
      const rows = await listReceipts(db(), id, Number(opts.limit));
      if (!rows.length) return console.log(dim("no receipts yet"));
      for (const r of rows.reverse()) {
        const c = r.sync_counts ?? {};
        console.log(
          `#${String(r.id).padEnd(5)} ${String(r.created_at).slice(0, 19)}  ${String(r.stream).padEnd(10)} ${(DECISION_COLOR[r.decision] ?? ((x: string) => x))(String(r.decision).padEnd(14))}` +
            ` published=${r.records_published ?? 0}` + (c.seen !== undefined ? ` seen=${c.seen} quarantined=${c.quarantined}` : "") +
            dim(`  sha256:${String(r.digest).slice(0, 12)}… ${r.anchored_seq ? `anchored #${r.anchored_seq}` : "NOT anchored"}`),
        );
      }
    }),
  );

program
  .command("receipt")
  .description("show one receipt and verify it: digest recomputed from the body, and compared with its ledger anchor")
  .argument("<receiptId>")
  .option("--json", "print the full receipt body")
  .action(
    action(async (rid: string, opts: { json?: boolean }) => {
      const id = Number(rid);
      const r = (await db().query("select * from sync_receipts where id = $1", [id])).rows[0];
      if (!r) throw new Error(`receipt ${rid} not found`);
      const v = (await verifyReceipt(db(), id))!;
      if (opts.json) return console.log(JSON.stringify(r.body, null, 2));
      const b = r.body;
      console.log(`receipt #${r.id}  ${r.connector_id}/${r.stream}  ${(DECISION_COLOR[r.decision] ?? ((x: string) => x))(r.decision)}  published=${r.published}`);
      console.log(dim(`  sync ${r.sync_id}  run ${r.run_id ?? "-"}  config v${b.connector?.config_version ?? "?"} ${String(b.connector?.config_hash ?? "").slice(0, 12)}…`));
      if (b.counts?.sync) console.log(`  sync totals: ${b.counts.sync.pages} pages, ${b.counts.sync.seen} seen, ${b.counts.sync.accepted} accepted, ${b.counts.sync.quarantined} quarantined`);
      if (b.pagination) console.log(`  pagination: ${b.pagination.termination}`);
      if (b.schema) console.log(`  schema: ${String(b.schema.fingerprint).slice(0, 12)}… (${b.schema.paths} paths)${b.schema.breaking?.length ? yellow(`  breaking: ${b.schema.breaking.join("; ")}`) : ""}`);
      if (b.freshness?.newest_record_at) console.log(`  newest record: ${b.freshness.newest_record_at}`);
      for (const x of b.reasons ?? []) console.log(`  reason: ${x}`);
      for (const x of b.inferences ?? []) console.log(dim(`  inferred: ${x}`));
      console.log(
        `  verify: digest ${v.digestMatches ? green("matches body") : red("DOES NOT match body")}` +
          `, ledger anchor ${v.anchored ? (v.anchorMatches ? green(`matches (ledger #${r.anchored_seq})`) : red("DOES NOT match")) : yellow("missing")}`,
      );
      console.log(dim(`  not claimed: ${(b.not_claimed ?? []).join("; ")}`));
      if (!v.digestMatches || (v.anchored && !v.anchorMatches)) process.exitCode = 1;
    }),
  );

program
  .command("held")
  .description("syncs held for review (schema change, too much quarantine, too few records): nothing was published")
  .action(
    action(async () => {
      const rows = await listHeld(db());
      if (!rows.length) return console.log(dim("nothing held"));
      for (const r of rows) console.log(`${r.sync_id}  ${r.connector_id}/${r.stream}  ${r.records} records staged  ${String(r.created_at).slice(0, 19)}\n  ${yellow(r.held_reason ?? "")}`);
    }),
  );

for (const [name, action_] of [["approve", "publish a held sync's staged records"], ["discard", "drop a held sync's staged records"]] as const)
  program
    .command(name)
    .description(`${action_} (leaves its own receipt, anchored in the ledger)`)
    .argument("<syncId>")
    .action(
      action(async (syncId: string) => {
        const r = await resolveHeldSync(db(), syncId, name, process.env.USER ?? "cli");
        const anchored = await broker().anchorReceipt!(r.receiptId).then(() => true, () => false);
        console.log(`${green("✔")} ${name === "approve" ? `published ${r.records}` : `discarded ${r.records}`} records of ${r.connectorId}; receipt #${r.receiptId}${anchored ? "" : yellow(" (not anchored: broker unreachable)")}`);
      }),
    );

/** ix run through the job queue: one execution path for manual and scheduled runs. Waits for the worker's result. */
async function runQueued(id: string, streams: number): Promise<void> {
  const boss = await startBoss(process.env.DATABASE_URL_APP!);
  try {
    const t0 = new Date(Date.now() - 1000);
    const jobId = await enqueueRun(boss, { connectorId: id, trigger: "manual" });
    if (!jobId) {
      console.log(yellow(`⏳ a run of ${id} is already queued or running; follow it with: ix runs ${id}`));
      return;
    }
    console.log(dim(`queued ${id} (job ${jobId}); waiting for the worker…`));
    const started = Date.now();
    for (;;) {
      await new Promise((r) => setTimeout(r, 1000));
      const rows = (
        await db().query(
          `select r.id, r.stream, r.status, r.requests, r.records_ok, r.records_quarantined, r.retries, r.rate_limited_ms, r.resumed, r.last_error,
                  s.id as receipt_id, s.decision, s.digest, s.sync_id, (s.body->>'records_published')::int as published
           from runs r left join sync_receipts s on s.run_id = r.id and s.kind = 'run'
           where r.connector_id = $1 and r.started_at >= $2 order by r.started_at`,
          [id, t0],
        )
      ).rows;
      if (!rows.length && Date.now() - started > 20_000) {
        console.log(yellow("no worker picked the job up in 20 s: is the platform running (pnpm dev)? The job stays queued. Or run it here: ix run --local " + id));
        process.exitCode = 2;
        return;
      }
      if (rows.length < streams || rows.some((r) => r.status === "running")) continue;
      for (const r of rows) {
        console.log(
          `${String(r.stream).padEnd(12)} ${paint(r.status).padEnd(tty ? 21 : 12)} requests=${r.requests} ok=${r.records_ok} quarantined=${r.records_quarantined}` +
            (r.retries ? ` retries=${r.retries}` : "") + (r.rate_limited_ms ? ` waited=${(r.rate_limited_ms / 1000).toFixed(1)}s` : "") +
            (r.resumed ? yellow(" (resumed from checkpoint)") : "") + (r.last_error ? dim(`  ${r.last_error}`) : ""),
        );
        if (r.decision)
          console.log(
            `${"".padEnd(13)}${DECISION_COLOR[r.decision]?.(r.decision) ?? r.decision} · published ${r.published ?? 0}` +
              dim(` · receipt #${r.receipt_id} sha256:${String(r.digest).slice(0, 12)}…`) +
              (r.decision === "held" ? yellow(`  → review: ix held · ix approve ${r.sync_id} · ix discard ${r.sync_id}`) : ""),
          );
      }
      if (rows.some((r) => !["success", "partial", "paused"].includes(r.status))) process.exitCode = 1;
      return;
    }
  } finally {
    await boss.stop({ graceful: false }).catch(() => {});
  }
}

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
      console.log(`  policy violations (7d): ${p.violations_7d}${p.violation_entries_7d !== p.violations_7d ? dim(` (${p.violation_entries_7d} ledger entries)`) : ""}${p.last_violation ? dim(`  last: ${String(p.last_violation.ts).slice(0, 19)} ${p.last_violation.decision}`) : ""}`);
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
