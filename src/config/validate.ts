// Config validation (B-2): YAML syntax -> interpolation -> Zod structure -> cross-field/policy rules.
// Every issue carries a dotted path and a 1-based line:col in the source file.
import { parseRanges, splitRanges } from "./ipranges.ts";
import { createHash } from "node:crypto";
import { LineCounter, isMap, isScalar, isSeq, parseDocument, visit, type Document } from "yaml";
import { methodAllowed, hostAllowed, pathAllowed } from "../broker/policy.ts";
import { parsePath, PathSyntaxError } from "../mapping/paths.ts";
import { findSecrets } from "../mapping/scanner.ts";
import { interpolate } from "./interpolate.ts";
import {
  ConnectorSchema, ENTITY_FIELDS, SEVERITIES, connectorJsonSchema,
  type ConnectorConfig, type FieldSpec,
} from "./schema.ts";

export type Severity = "error" | "warning";
export type Issue = { severity: Severity; path: string; line: number; col: number; message: string };
export type ValidationResult = {
  ok: boolean;
  errors: Issue[];
  warnings: Issue[];
  config?: ConnectorConfig; // interpolated, only when ok
  configHash: string; // sha256 of source text
};
type P = (string | number)[];

export function formatPath(path: P): string {
  let s = "";
  for (const seg of path) s += typeof seg === "number" ? `[${seg}]` : s ? `.${seg}` : seg;
  return s || "(root)";
}

// ---------- source locations ----------
class Locator {
  private doc: Document;
  private lc: LineCounter;
  constructor(doc: Document, lc: LineCounter) {
    this.doc = doc;
    this.lc = lc;
  }
  /** Position of the deepest existing node on `path`, preferring the key token. `key` targets a child key. */
  at(path: P, key?: string): { line: number; col: number } {
    let node: unknown = this.doc.contents;
    let offset = rangeStart(node) ?? 0;
    const full = key === undefined ? path : [...path, key];
    for (const seg of full) {
      if (isMap(node)) {
        const pair = node.items.find((p) => isScalar(p.key) && String(p.key.value) === String(seg));
        if (!pair) break;
        offset = rangeStart(pair.key) ?? offset;
        node = pair.value;
      } else if (isSeq(node) && typeof seg === "number") {
        const item = node.items[seg];
        if (!item) break;
        offset = rangeStart(item) ?? offset;
        node = item;
      } else break;
    }
    return this.lc.linePos(offset);
  }
}
function rangeStart(node: unknown): number | undefined {
  const r = (node as { range?: [number, number, number] } | null)?.range;
  return r ? r[0] : undefined;
}

// ---------- helpers ----------
function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0]!;
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j]!;
      dp[j] = Math.min(dp[j]! + 1, dp[j - 1]! + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length]!;
}
let vocab: string[] | undefined;
function knownKeys(): string[] {
  if (vocab) return vocab;
  const set = new Set<string>();
  const walk = (s: unknown): void => {
    if (Array.isArray(s)) return s.forEach(walk);
    if (!s || typeof s !== "object") return;
    const o = s as Record<string, unknown>;
    if (o.properties && typeof o.properties === "object") Object.keys(o.properties).forEach((k) => set.add(k));
    Object.values(o).forEach(walk);
  };
  walk(connectorJsonSchema());
  return (vocab = [...set]);
}
function suggest(word: string, candidates: readonly string[]): string {
  let best: string | undefined;
  let bestD = Infinity;
  for (const c of candidates) {
    const d = levenshtein(word.toLowerCase(), c.toLowerCase());
    if (d < bestD) [best, bestD] = [c, d];
  }
  return best && bestD <= Math.max(2, Math.floor(word.length / 4)) ? ` (did you mean "${best}"?)` : "";
}
function getIn(obj: unknown, path: P): unknown {
  let v = obj;
  for (const seg of path) {
    if (v === null || typeof v !== "object") return undefined;
    v = (v as Record<string | number, unknown>)[seg];
  }
  return v;
}
export function durationMs(s: string): number {
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(s);
  if (!m) throw new Error(`bad duration ${s}`);
  const n = Number(m[1]);
  return n * { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "ms" | "s" | "m" | "h" | "d"];
}
function globToRe(glob: string): RegExp {
  return new RegExp(`^${glob.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");
}

const AUTH_TYPES = ["none", "api_key", "basic", "bearer", "oauth2_client_credentials"];
const PAGINATION_TYPES = ["link_header", "offset", "page_number", "cursor", "none"];
const CREDENTIAL_HEADERS = ["authorization", "proxy-authorization", "cookie", "x-api-key", "api-key", "apikey", "x-auth-token", "private-token"];
const CREDENTIAL_PARAMS = ["api_key", "apikey", "access_token", "token", "key", "password", "client_secret"];
const WRITE_SCOPE_RE = /(manage|write|admin|delete|:all$)/i;

// ---------- main ----------
export function validateConfigText(text: string, opts: { env?: Record<string, string | undefined> } = {}): ValidationResult {
  const env = opts.env ?? process.env;
  const configHash = createHash("sha256").update(text).digest("hex");
  const errors: Issue[] = [];
  const warnings: Issue[] = [];
  const lc = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lc, schema: "core", merge: false, uniqueKeys: true, prettyErrors: true });
  const loc = new Locator(doc, lc);
  const add = (severity: Severity, path: P, message: string, key?: string): void => {
    const { line, col } = loc.at(path, key);
    (severity === "error" ? errors : warnings).push({
      severity, path: formatPath(key === undefined ? path : [...path, key]), line, col, message,
    });
  };
  const done = (config?: ConnectorConfig): ValidationResult => {
    const byLine = (a: Issue, b: Issue) => a.line - b.line || a.col - b.col;
    errors.sort(byLine);
    warnings.sort(byLine);
    return { ok: errors.length === 0, errors, warnings, configHash, ...(errors.length === 0 && config ? { config } : {}) };
  };

  // 1. YAML syntax and safety: no custom tags, no anchors/aliases, no merge keys.
  for (const e of [...doc.errors, ...doc.warnings]) {
    const pos = e.linePos?.[0] ?? { line: 1, col: 1 };
    errors.push({ severity: "error", path: "(yaml)", line: pos.line, col: pos.col, message: e.message.split("\n")[0]! });
  }
  if (errors.length) return done();
  visit(doc, {
    Alias(_, node) {
      const p = lc.linePos(node.range?.[0] ?? 0);
      errors.push({ severity: "error", path: "(yaml)", ...p, message: "YAML aliases (*ref) are not allowed in connector configs" });
    },
    Node(_, node) {
      if (node.tag) {
        const p = lc.linePos(node.range?.[0] ?? 0);
        errors.push({ severity: "error", path: "(yaml)", ...p, message: `explicit YAML tag ${node.tag} is not allowed` });
      }
    },
  });
  if (errors.length) return done();
  const raw = doc.toJS({ maxAliasCount: 0 }) as unknown;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    errors.push({ severity: "error", path: "(root)", line: 1, col: 1, message: "config must be a YAML mapping" });
    return done();
  }

  // 2. Literal secrets anywhere in the file.
  const scanSecrets = (v: unknown, path: P): void => {
    if (typeof v === "string") {
      const kinds = findSecrets(v);
      if (kinds.length) add("error", path, `value looks like a literal secret (${kinds.join(", ")}); use "ix secret set" and a *_ref`);
    } else if (Array.isArray(v)) v.forEach((x, i) => scanSecrets(x, [...path, i]));
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) scanSecrets(x, [...path, k]);
  };
  scanSecrets(raw, []);

  // 3. ${env.X} interpolation.
  const interp = interpolate(raw, env);
  for (const i of interp.issues) add("error", i.path, i.message);

  // 4. Structure.
  const parsed = ConnectorSchema.safeParse(interp.value);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      const path = issue.path as P;
      const iss = issue as typeof issue & { keys?: string[]; discriminator?: string; note?: string };
      if (iss.code === "unrecognized_keys" && iss.keys) {
        for (const k of iss.keys) add("error", path, `unknown key "${k}"${suggest(k, knownKeys())}`, k);
        continue;
      }
      if (iss.code === "invalid_union" && iss.discriminator) {
        const objPath = path[path.length - 1] === iss.discriminator ? path.slice(0, -1) : path;
        const got = getIn(interp.value, [...objPath, iss.discriminator]);
        const parent = objPath[objPath.length - 1];
        const options = parent === "auth" ? AUTH_TYPES : parent === "pagination" ? PAGINATION_TYPES : [];
        const g = got === undefined ? "missing" : `"${String(got)}"`;
        add("error", [...objPath, iss.discriminator],
          `${iss.discriminator} is ${g}; expected one of: ${options.join(", ")}${typeof got === "string" ? suggest(got, options) : ""}`);
        continue;
      }
      const got = getIn(interp.value, path);
      if (got === undefined && iss.code === "invalid_type") {
        add("error", path, `missing required key "${String(path[path.length - 1])}"`);
        continue;
      }
      const shown = typeof got === "string" || typeof got === "number" || typeof got === "boolean" ? ` (got ${JSON.stringify(got)})` : "";
      add("error", path, `${issue.message}${shown}`);
    }
    return done();
  }
  if (errors.length) return done();
  const cfg = parsed.data;

  // 5. Cross-field and policy rules.
  semanticChecks(cfg, add);
  policyWarnings(cfg, add);
  return done(cfg);
}

type Add = (severity: Severity, path: P, message: string, key?: string) => void;

function checkPath(add: Add, path: P, expr: string | undefined): void {
  if (expr === undefined) return;
  try {
    parsePath(expr);
  } catch (e) {
    if (e instanceof PathSyntaxError) add("error", path, `bad path: ${e.message}`);
    else throw e;
  }
}

function semanticChecks(cfg: ConnectorConfig, add: Add): void {
  const policy = cfg.policy;
  const methods = policy.methods ?? ["GET"];

  // base_url
  let base: URL | undefined;
  try {
    base = new URL(cfg.connection.base_url);
  } catch {
    add("error", ["connection", "base_url"], `not a valid URL: ${cfg.connection.base_url}`);
  }
  const isLocal = (h: string) => ["localhost", "127.0.0.1", "[::1]"].includes(h);
  if (base) {
    if (base.username || base.password) add("error", ["connection", "base_url"], "credentials in base_url are not allowed; use connection.auth");
    if (base.search || base.hash) add("error", ["connection", "base_url"], "base_url must not contain a query or fragment; use request.params");
    if (base.protocol !== "https:" && !(base.protocol === "http:" && isLocal(base.hostname)))
      add("error", ["connection", "base_url"], "base_url must use https:// (http:// only for localhost mocks)");
    if (!hostAllowed(base.hostname, policy.allowed_hosts))
      add("error", ["connection", "base_url"], `host ${base.hostname} is outside policy.allowed_hosts [${policy.allowed_hosts.join(", ")}]`);
  }
  const basePrefix = base ? base.pathname.replace(/\/$/, "") : "";

  // auth
  const auth = cfg.connection.auth;
  const ap: P = ["connection", "auth"];
  if (auth.type === "api_key" && auth.in === "query")
    add("warning", [...ap, "in"], "API key in the query string can leak into provider and proxy logs; prefer in: header");
  if (auth.type === "oauth2_client_credentials") {
    if (auth.client_auth === "private_key_jwt" && !auth.private_key_ref)
      add("error", ap, "client_auth private_key_jwt requires private_key_ref", "client_auth");
    if (auth.client_auth !== "private_key_jwt" && !auth.client_secret_ref)
      add("error", ap, `client_auth ${auth.client_auth} requires client_secret_ref`, "client_auth");
    if (auth.client_auth === "private_key_jwt" && auth.client_secret_ref)
      add("warning", [...ap, "client_secret_ref"], "client_secret_ref is ignored with private_key_jwt");
    let tokenUrl: URL | undefined;
    try {
      tokenUrl = new URL(auth.token_url, cfg.connection.base_url);
    } catch {
      add("error", [...ap, "token_url"], `not a valid URL: ${auth.token_url}`);
    }
    if (tokenUrl) {
      if (tokenUrl.protocol !== "https:" && !(tokenUrl.protocol === "http:" && isLocal(tokenUrl.hostname)))
        add("error", [...ap, "token_url"], "token_url must use https://");
      if (!hostAllowed(tokenUrl.hostname, policy.allowed_hosts))
        add("error", [...ap, "token_url"], `token host ${tokenUrl.hostname} is outside policy.allowed_hosts`);
      if (policy.allowed_paths && !pathAllowed(tokenUrl.pathname, policy.allowed_paths))
        add("error", [...ap, "token_url"], `token path ${tokenUrl.pathname} is not in policy.allowed_paths`);
    }
    if (auth.revocation_url) {
      let rev: URL | undefined;
      try {
        rev = new URL(auth.revocation_url, cfg.connection.base_url);
      } catch {
        add("error", [...ap, "revocation_url"], `not a valid URL: ${auth.revocation_url}`);
      }
      if (rev && !hostAllowed(rev.hostname, policy.allowed_hosts))
        add("error", [...ap, "revocation_url"], `revocation host ${rev.hostname} is outside policy.allowed_hosts`);
    }
    const forbid = cfg.credential?.forbid_scopes ?? [];
    (auth.scopes ?? []).forEach((s, i) => {
      const hit = forbid.find((f) => globToRe(f).test(s));
      if (hit) add("error", [...ap, "scopes", i], `scope ${s} matches credential.forbid_scopes "${hit}"`);
      else if (WRITE_SCOPE_RE.test(s)) add("warning", [...ap, "scopes", i], `scope ${s} looks like a write/admin scope; connectors only read`);
    });
  }

  // streams
  const names = new Set<string>();
  cfg.streams.forEach((st, si) => {
    const sp: P = ["streams", si];
    if (names.has(st.name)) add("error", [...sp, "name"], `duplicate stream name "${st.name}"`);
    names.add(st.name);

    const fullPath = basePrefix + st.request.path;
    const rp: P = [...sp, "request"];
    if (st.request.method === "POST") {
      // Read-only POST: only for search endpoints the policy declares explicitly.
      if (!policy.read_only_post || !pathAllowed(fullPath, policy.read_only_post))
        add("error", [...rp, "method"], `POST to ${fullPath} needs the path in policy.read_only_post (read-only search endpoints only)`);
      else
        add("warning", [...rp, "method"], "read-only POST: the broker allows POST only to policy.read_only_post paths, but cannot verify the endpoint has no side effects");
      if (!st.request.body) add("error", rp, "POST requests need a request.body (the search query)", "method");
    } else {
      if (!methodAllowed(st.request.method, methods)) add("error", [...rp, "method"], `method ${st.request.method} not in policy.methods`);
      if (policy.allowed_paths && !pathAllowed(fullPath, policy.allowed_paths))
        add("error", [...rp, "path"], `path ${fullPath} is not in policy.allowed_paths`);
      if (st.request.body) add("error", [...rp, "body"], "request.body is only allowed with method POST");
    }
    if (st.request.paging_in === "body" && st.request.method !== "POST") add("error", [...rp, "paging_in"], "paging_in: body requires method POST");
    if (st.request.path.includes("?")) add("error", [...rp, "path"], "put query parameters in request.params, not the path");
    for (const h of Object.keys(st.request.headers ?? {}))
      if (CREDENTIAL_HEADERS.includes(h.toLowerCase()))
        add("error", [...sp, "request", "headers"], `header ${h} carries credentials; configure it in connection.auth`, h);
    for (const k of Object.keys(st.request.params ?? {}))
      if (CREDENTIAL_PARAMS.includes(k.toLowerCase()))
        add("error", [...sp, "request", "params"], `param ${k} looks like a credential; configure it in connection.auth`, k);

    checkPath(add, [...sp, "records_path"], st.records_path);
    (st.detect ?? []).forEach((d, di) => {
      const dp: P = [...sp, "detect", di];
      checkPath(add, [...dp, "ip_path"], d.ip_path);
      for (const k of Object.keys(d.match)) checkPath(add, [...dp, "match"], k);
      const { entries, invalid } = splitRanges(d.allowed_ips);
      for (const x of invalid) add("error", [...dp, "allowed_ips"], `"${x}" is not an IP address or CIDR range`);
      if (!entries.length && !invalid.length) add("error", [...dp, "allowed_ips"], "allowed_ips is empty");
      if (!Object.keys(d.match).length) add("warning", [...dp, "match"], "no match fields: every record with an outside IP will alert");
    });

    const pg = st.pagination;
    const pp: P = [...sp, "pagination"];
    if (pg.type === "offset") checkPath(add, [...pp, "total_path"], pg.total_path);
    if (pg.type === "body_link") checkPath(add, [...pp, "next_path"], pg.next_path);
    if ((pg.type === "link_header" || pg.type === "body_link") && st.request.paging_in === "body")
      add("error", [...rp, "paging_in"], `paging_in: body has no effect with ${pg.type} pagination`);
    if (pg.type === "cursor") {
      if (!!pg.token_path === !!pg.token_header) add("error", pp, "cursor pagination needs exactly one of token_path or token_header");
      checkPath(add, [...pp, "token_path"], pg.token_path);
      if (pg.stop_when === "is_last_path" && !pg.is_last_path) add("error", pp, "stop_when is_last_path requires is_last_path", "stop_when");
      checkPath(add, [...pp, "is_last_path"], pg.is_last_path);
    }

    if (st.incremental) {
      const ip: P = [...sp, "incremental"];
      checkPath(add, [...ip, "cursor_field"], st.incremental.cursor_field);
      for (const [k, t] of Object.entries(st.incremental.extra_params ?? {}))
        for (const m of t.matchAll(/\{\{([^}]*)\}\}/g))
          if (!["cursor", "now"].includes(m[1]!.trim())) add("error", [...ip, "extra_params", k], `unknown template variable {{${m[1]}}}; use {{cursor}} or {{now}}`);
      if (st.incremental.initial && !/^-\d+[mhd]$/.test(st.incremental.initial) && Number.isNaN(Date.parse(st.incremental.initial)))
        add("error", [...ip, "initial"], 'initial must be an ISO date or relative like "-7d"');
    }

    checkMapping(add, sp, st.entity, st.mapping);
  });

  // schedule
  if (cfg.schedule) {
    if (durationMs(cfg.schedule.every) < 60_000) add("error", ["schedule", "every"], "schedule.every must be at least 1m");
    if (cfg.schedule.jitter && durationMs(cfg.schedule.jitter) >= durationMs(cfg.schedule.every))
      add("error", ["schedule", "jitter"], "jitter must be shorter than every");
  }

  // data minimisation
  if (cfg.data?.store_raw && cfg.data.redact_secrets === false)
    add("error", ["data", "redact_secrets"], "store_raw requires redact_secrets: true");
}

function checkMapping(add: Add, sp: P, entity: keyof typeof ENTITY_FIELDS, mapping: Record<string, FieldSpec>): void {
  const mp: P = [...sp, "mapping"];
  const allowed: readonly string[] = ENTITY_FIELDS[entity];
  if (!mapping.id) add("error", mp, `mapping must define "id" (the provider's stable record id)`);
  if (entity === "event" && !mapping.type) add("error", mp, `event mapping must define "type"`);
  for (const [field, spec] of Object.entries(mapping)) {
    const fp: P = [...mp, field];
    if (field === "source" || field === "fetched_at") {
      add("error", fp, `${field} is set automatically from metadata/run time; remove it from mapping`);
      continue;
    }
    if (!allowed.includes(field)) {
      add("error", fp, `unknown field "${field}" for entity ${entity}${suggest(field, allowed)}; allowed: ${allowed.join(", ")}`);
      continue;
    }
    const sources = (["path", "const", "concat", "pick"] as const).filter((k) => spec[k] !== undefined);
    if (sources.length !== 1) {
      add("error", fp, `field needs exactly one of path, const, concat, pick (found ${sources.length ? sources.join(", ") : "none"})`);
      continue;
    }
    if (spec.pick && field !== "attributes") add("error", fp, "pick is only allowed for attributes", "pick");
    if (field === "attributes" && !spec.pick) add("error", fp, "attributes must use pick: [paths]");
    const paths = spec.path === undefined ? [] : Array.isArray(spec.path) ? spec.path : [spec.path];
    paths.forEach((p, i) => checkPath(add, Array.isArray(spec.path) ? [...fp, "path", i] : [...fp, "path"], p));
    spec.concat?.forEach((c, i) => typeof c === "string" && checkPath(add, [...fp, "concat", i], c));
    spec.pick?.forEach((p, i) => checkPath(add, [...fp, "pick", i], p));

    const transforms = spec.transform === undefined ? [] : Array.isArray(spec.transform) ? spec.transform : [spec.transform];
    if (transforms.includes("cvss_to_severity") && field !== "severity")
      add("warning", [...fp, "transform"], "cvss_to_severity is meant for the severity field");
    if (field === "severity") {
      const sev: readonly string[] = SEVERITIES;
      if (spec.const !== undefined && !sev.includes(String(spec.const)))
        add("error", [...fp, "const"], `severity must be one of: ${sev.join(", ")}`);
      for (const [k, v] of Object.entries(spec.map_enum ?? {}))
        if (!sev.includes(v)) add("error", [...fp, "map_enum", k], `severity must be one of: ${sev.join(", ")} (got "${v}")`);
      if (spec.default !== undefined && spec.default !== null && !sev.includes(String(spec.default)))
        add("error", [...fp, "default"], `severity default must be one of: ${sev.join(", ")}`);
      if (spec.path !== undefined && !spec.map_enum && !transforms.includes("cvss_to_severity"))
        add("warning", fp, "severity from a raw path without map_enum or cvss_to_severity; values outside the enum will be quarantined");
    }
    if (spec.required && spec.const !== undefined) add("warning", [...fp, "required"], "required has no effect on a const field");
  }
}

function policyWarnings(cfg: ConnectorConfig, add: Add): void {
  if (!cfg.policy.allowed_paths && cfg.streams.some((s) => s.request.method === "GET"))
    add("warning", ["policy"], "allowed_paths not set; the broker will allow only the declared stream paths");
  if (!cfg.policy.max_requests_per_run) add("warning", ["policy"], "max_requests_per_run not set; defaulting to 1000");
  if (!cfg.schedule) add("warning", [], "no schedule; this connector runs only on demand (ix run)");
  if (!cfg.reliability?.rate_limit?.requests_per_minute)
    add("warning", [], "no reliability.rate_limit.requests_per_minute; defaulting to 60");
  if (cfg.connection.auth.type !== "none" && !cfg.credential)
    add("warning", [], "authenticated connector without a credential block (max_age_days, idle_disable_days, scopes)");
  if (cfg.credential?.provider_ip_restriction === "no")
    add("warning", ["credential", "provider_ip_restriction"], "token is usable from any IP; a stolen copy works anywhere");
  const allow = cfg.credential?.provider_ip_allowlist;
  if (allow) {
    const { invalid } = splitRanges(allow);
    for (const x of invalid) add("error", ["credential", "provider_ip_allowlist"], `"${x}" is not an IP address or CIDR range`);
    if (parseRanges(allow).any) add("warning", ["credential", "provider_ip_allowlist"], "the allow-list includes /0: it allows every IP");
    if (cfg.credential?.provider_ip_restriction === "no")
      add("error", ["credential", "provider_ip_restriction"], "provider_ip_restriction: no contradicts provider_ip_allowlist");
  }
}

