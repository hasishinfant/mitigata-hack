// Posture card: what a connector can reach and what its credential could do if stolen ("blast radius"),
// with risk flags. Reads config, credential metadata (via the credential_meta view: no ciphertext) and
// the audit ledger. Uses the app DB role only.
import type pg from "pg";
import type { ResolvedConnector } from "../config/load.ts";
import { loadActiveConnector } from "../store/connectors.ts";
import { assessScopes, type ScopeAssessment } from "./scopes.ts";

export type Level = "high" | "medium" | "low";
export type Flag = { level: Level; message: string };
export type CredentialState = {
  ref: string;
  stored: boolean;
  age_days: number | null;
  idle_days: number | null;
  last_used_at: string | null;
  granted_scopes: string[] | null;
  scopes_seen_at: string | null;
};
export type Posture = {
  connector_id: string;
  source: string;
  status: string;
  auth_type: string;
  streams: { name: string; entity: string; method: string; path: string; fields: { name: string; sources: string[] }[] }[];
  reach: { allowed_hosts: string[]; allowed_paths: string[]; read_only_post: string[]; methods: string[]; max_requests_per_run: number; max_records_per_run: number };
  credentials: CredentialState[];
  scopes: ScopeAssessment & { source: "token_response" | "response_header" | "unknown" };
  revocable_by_api: boolean | "unknown";
  provider_ip_restriction: "yes" | "no" | "unknown";
  revoke_hint: string | null;
  limits: { max_age_days: number | null; idle_disable_days: number | null };
  data: { store_raw: boolean; retention_days: number | null };
  violations_7d: number;
  last_violation: { ts: string; decision: string } | null;
  risk: Level;
  flags: Flag[];
};

const RANK: Record<Level, number> = { low: 1, medium: 2, high: 3 };

import { credentialRefs } from "../config/load.ts";
export { credentialRefs };

const days = (from: string | null, now: number) => (from ? Math.floor((now - Date.parse(from)) / 86_400_000) : null);

/** Pure: derive flags and overall risk from the facts gathered for a connector. */
export function deriveFlags(p: Omit<Posture, "risk" | "flags">): Flag[] {
  const flags: Flag[] = [];
  const s = p.scopes;
  for (const f of s.forbidden) flags.push({ level: "high", message: `forbidden scope granted: ${f}` });
  for (const w of s.writeLike.filter((x) => !s.forbidden.includes(x))) flags.push({ level: "high", message: `over-privileged: token can ${w} (connector only reads)` });
  const benignExtra = s.extra.filter((x) => !s.writeLike.includes(x) && !s.forbidden.includes(x));
  if (benignExtra.length) flags.push({ level: "medium", message: `more scopes than expected: ${benignExtra.join(", ")}` });
  if (s.missing.length) flags.push({ level: "low", message: `expected scopes not granted: ${s.missing.join(", ")}` });
  if (p.violations_7d > 0) flags.push({ level: "high", message: `${p.violations_7d} policy violation(s) in the last 7 days` });
  for (const c of p.credentials) {
    if (!c.stored) flags.push({ level: "medium", message: `secret ${c.ref} is not stored` });
    if (c.age_days !== null && p.limits.max_age_days !== null && c.age_days > p.limits.max_age_days)
      flags.push({ level: "medium", message: `rotate ${c.ref}: ${c.age_days} days old (max ${p.limits.max_age_days})` });
    if (c.idle_days !== null && p.limits.idle_disable_days !== null && c.idle_days > p.limits.idle_disable_days)
      flags.push({ level: "medium", message: `${c.ref} unused for ${c.idle_days} days (idle limit ${p.limits.idle_disable_days})` });
  }
  if (p.auth_type !== "none") {
    if (p.provider_ip_restriction === "no") flags.push({ level: "medium", message: "token works from any IP: a stolen copy is usable anywhere" });
    if (p.provider_ip_restriction === "unknown") flags.push({ level: "low", message: "provider IP restriction unknown" });
    if (p.revocable_by_api !== true) flags.push({ level: "low", message: "manual revocation only (panic can't revoke it for you)" });
    if (s.granted === null) flags.push({ level: "low", message: "provider did not report granted scopes" });
  }
  if (p.data.store_raw) flags.push({ level: "low", message: "stores raw payloads (secret-redacted)" });
  return flags.sort((a, b) => RANK[b.level] - RANK[a.level]);
}

export async function getPosture(pool: pg.Pool, id: string, env: Record<string, string | undefined> = process.env): Promise<Posture> {
  const conn = await loadActiveConnector(pool, id, env);
  const now = Date.now();
  const refs = credentialRefs(conn);
  const meta = refs.length
    ? (await pool.query("select ref, created_at, last_used_at, granted_scopes, scopes_seen_at, revocable_by_api from credential_meta where tenant_id = $1 and ref = any($2)", [conn.metadata.tenant, refs])).rows
    : [];
  const byRef = new Map(meta.map((m) => [m.ref as string, m]));
  const credentials: CredentialState[] = refs.map((ref) => {
    const m = byRef.get(ref);
    return {
      ref, stored: Boolean(m), age_days: days(m?.created_at ?? null, now), idle_days: m ? days(m.last_used_at ?? m.created_at, now) : null,
      last_used_at: m?.last_used_at ?? null, granted_scopes: m?.granted_scopes ?? null, scopes_seen_at: m?.scopes_seen_at ?? null,
    };
  });
  const primary = credentials.find((c) => c.granted_scopes) ?? credentials[0];
  const a = conn.connection.auth;
  const scopes = assessScopes(primary?.granted_scopes ?? null, conn.credential?.expected_scopes ?? [], conn.credential?.forbid_scopes ?? []);
  const scopeSource = primary?.granted_scopes ? (a.type === "oauth2_client_credentials" ? "token_response" : "response_header") : "unknown";
  const revocableMeta = meta.find((m) => m.revocable_by_api !== null)?.revocable_by_api as boolean | undefined;
  const v = (
    await pool.query(
      `select count(*) filter (where ts > now() - interval '7 days')::int as n,
              (array_agg(ts order by seq desc))[1] as ts, (array_agg(decision order by seq desc))[1] as decision
       from audit_ledger where connector_id = $1 and decision like 'deny%'`,
      [id],
    )
  ).rows[0];
  const status = (await pool.query("select status from connectors where id = $1", [id])).rows[0]?.status ?? "unknown";

  const base: Omit<Posture, "risk" | "flags"> = {
    connector_id: id,
    source: conn.metadata.source,
    status,
    auth_type: a.type,
    streams: conn.streams.map((s) => ({
      name: s.name,
      entity: s.entity,
      method: s.request.method,
      path: s.request.path,
      fields: Object.entries(s.mapping).map(([name, spec]) => ({
        name,
        sources: [
          ...(typeof spec.path === "string" ? [spec.path] : spec.path ?? []),
          ...(spec.pick ?? []),
        ],
      })),
    })),
    reach: {
      allowed_hosts: conn.policy.allowed_hosts, allowed_paths: conn.runtime.allowedPaths, read_only_post: conn.runtime.readOnlyPost,
      methods: conn.runtime.methods, max_requests_per_run: conn.runtime.maxRequestsPerRun, max_records_per_run: conn.runtime.maxRecordsPerRun,
    },
    credentials,
    scopes: { ...scopes, source: scopeSource },
    revocable_by_api: conn.credential?.revocable_by_api ?? revocableMeta ?? (a.type === "oauth2_client_credentials" && a.revocation_url ? true : a.type === "none" ? false : "unknown"),
    provider_ip_restriction: conn.credential?.provider_ip_restriction ?? "unknown",
    revoke_hint: conn.credential?.revoke_hint ?? null,
    limits: { max_age_days: conn.credential?.max_age_days ?? null, idle_disable_days: conn.credential?.idle_disable_days ?? null },
    data: { store_raw: conn.data?.store_raw ?? false, retention_days: conn.data?.retention_days ?? null },
    violations_7d: v?.n ?? 0,
    last_violation: v?.ts ? { ts: v.ts, decision: v.decision } : null,
  };
  const flags = deriveFlags(base);
  const risk: Level = flags.reduce<Level>((r, f) => (RANK[f.level] > RANK[r] ? f.level : r), "low");
  return { ...base, risk, flags };
}
