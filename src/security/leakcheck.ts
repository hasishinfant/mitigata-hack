// Leak check: does any stored secret value appear anywhere it shouldn't?
// Decrypts every secret in memory (broker credentials required), then searches, in raw, base64 and
// URL-encoded form:
//   - every tracked or untracked-but-not-ignored file in the repo, plus .env
//   - any log files given as arguments
//   - a full pg_dump of the database (credentials table included: it should hold only ciphertext)
//   - the environment of running worker / api / scheduler processes (also checked for broker-only variable names)
// Prints secret *names* and locations, never values. Exit code 1 on any hit.
//
//   npx pnpm@10.28.0 leakcheck -- /tmp/ix-dev.log
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import pg from "pg";
import { parseMasterKey, unseal } from "../broker/secrets.ts";
import { BROKER_ONLY_VARS, loadBrokerEnv } from "../envfiles.ts";

export type Secret = { ref: string; value: string };
export type Target = { name: string; text: string };
export type Hit = { ref: string; target: string; form: string };

export function scanForSecrets(secrets: Secret[], targets: Target[]): Hit[] {
  const hits: Hit[] = [];
  for (const s of secrets) {
    if (s.value.length < 8) continue; // too short to search without false positives
    const forms: [string, string][] = [
      ["raw", s.value],
      ["base64", Buffer.from(s.value).toString("base64")],
      ["urlencoded", encodeURIComponent(s.value)],
    ];
    // For multi-line values (PEM keys) also search a distinctive middle line.
    const lines = s.value.split("\n").filter((l) => l.length >= 32 && !l.startsWith("-----"));
    if (lines.length) forms.push(["pem-line", lines[Math.floor(lines.length / 2)]!]);
    for (const t of targets)
      for (const [form, needle] of forms)
        if (needle && t.text.includes(needle)) {
          hits.push({ ref: s.ref, target: t.name, form });
          break;
        }
  }
  return hits;
}

function readTextFiles(paths: string[]): Target[] {
  const out: Target[] = [];
  for (const p of paths) {
    try {
      if (!existsSync(p) || statSync(p).size > 50 * 1024 * 1024) continue;
      out.push({ name: p, text: readFileSync(p, "latin1") });
    } catch {
      /* unreadable: skip */
    }
  }
  return out;
}

function processEnvs(): { targets: Target[]; brokerVarHits: string[] } {
  const targets: Target[] = [];
  const brokerVarHits: string[] = [];
  let ps = "";
  try {
    // -E/e: print each process environment after its command line; -x: include processes without a terminal.
    ps = execFileSync("ps", process.platform === "darwin" ? ["-Exww", "-o", "pid=,command="] : ["exww", "-o", "pid=,args="], { encoding: "latin1", maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return { targets, brokerVarHits };
  }
  for (const line of ps.split("\n")) {
    const m = /src\/(worker|api|scheduler)\/index\.ts/.exec(line);
    if (!m) continue;
    const pid = line.trim().split(/\s+/)[0];
    const name = `process ${m[1]} (pid ${pid}) environment`;
    targets.push({ name, text: line });
    for (const v of BROKER_ONLY_VARS) if (new RegExp(`(^|\\s)${v}=\\S`).test(line)) brokerVarHits.push(`${name}: ${v}`);
    if (/(^|\s)IX_SECRET_[A-Z0-9_]+=\S/.test(line)) brokerVarHits.push(`${name}: IX_SECRET_*`);
  }
  return { targets, brokerVarHits };
}

async function main(): Promise<void> {
  loadBrokerEnv();
  const masterKey = parseMasterKey(process.env.IX_MASTER_KEY);
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL_BROKER });
  const rows = (await pool.query("select tenant_id, ref, ciphertext, wrapped_dek, nonce from credentials")).rows;
  const secrets: Secret[] = rows.map((r) => ({
    ref: `${r.tenant_id}/${r.ref}`,
    value: unseal(masterKey, r.tenant_id, r.ref, { ciphertext: r.ciphertext, wrappedDek: r.wrapped_dek, nonce: r.nonce }),
  }));
  await pool.end();

  const repoFiles = execFileSync("git", ["ls-files", "-co", "--exclude-standard"], { encoding: "utf8" }).split("\n").filter(Boolean);
  const logArgs = process.argv.slice(2).filter((a) => a !== "--");
  const targets: Target[] = [...readTextFiles([...repoFiles, ".env"]), ...readTextFiles(logArgs)];

  let dumped = false;
  if (process.env.DATABASE_URL_ADMIN) {
    try {
      const dump = execFileSync("pg_dump", ["--data-only", process.env.DATABASE_URL_ADMIN], { encoding: "latin1", maxBuffer: 1024 * 1024 * 1024 });
      targets.push({ name: "pg_dump (all tables)", text: dump });
      dumped = true;
    } catch (e) {
      console.error(`pg_dump failed: ${(e as Error).message.split("\n")[0]}`);
    }
  }
  const procs = processEnvs();
  targets.push(...procs.targets);

  const hits = scanForSecrets(secrets, targets);
  console.log(`secrets checked: ${secrets.length} (${secrets.map((s) => s.ref).join(", ") || "none stored"})`);
  console.log(`searched: ${repoFiles.length} repo files + .env, ${logArgs.length} log file(s), ${dumped ? "full DB dump" : "no DB dump"}, ${procs.targets.length} running app process environment(s)`);
  for (const h of hits) console.log(`LEAK  ${h.ref} found in ${h.target} (${h.form})`);
  for (const b of procs.brokerVarHits) console.log(`LEAK  broker-only variable in ${b}`);
  if (hits.length || procs.brokerVarHits.length) {
    console.log(`✖ ${hits.length + procs.brokerVarHits.length} leak(s)`);
    process.exitCode = 1;
  } else console.log("✔ zero hits");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error((e as Error).message);
    process.exit(1);
  });
}
