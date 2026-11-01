// Connector capability registry: for each connector and each security control, whether IntegrateX enforces it,
// could enforce it (the provider supports it, it's just not enabled), only monitors it, can't (the provider doesn't
// support it), or whether it doesn't apply (a public, unauthenticated source has no credential to bind or revoke).
// Derived from the config, plus the optional `capabilities:` block where the operator declares what the provider
// supports. The point is to never pretend every API supports every control, and never flag what can't apply.
import type { ResolvedConnector } from "../config/load.ts";

export type CapabilityStatus = "enforced" | "available" | "monitored" | "unsupported" | "not_applicable" | "unknown";
export type Capability = { status: CapabilityStatus; detail: string };
export const CONTROLS = [
  "credential_broker", "egress_policy", "staged_integrity", "token_binding", "ip_allowlist",
  "foreign_ip_detection", "revocation", "rotation_hygiene",
] as const;
export type Control = (typeof CONTROLS)[number];
export type Capabilities = Record<Control, Capability>;

export function capabilitiesOf(conn: ResolvedConnector): Capabilities {
  const a = conn.connection.auth;
  const declared = conn.capabilities ?? {};
  const noCred = a.type === "none";
  const na = (detail: string): Capability => ({ status: "not_applicable", detail });
  const detectRules = conn.streams.reduce((n, s) => n + (s.detect?.length ?? 0), 0);

  const tokenBinding = (): Capability => {
    if (noCred) return na("public source: no credential");
    if (a.type !== "oauth2_client_credentials") return na(`${a.type}: a static key can't be bound to a key pair`);
    if (a.dpop) return { status: "enforced", detail: "DPoP: tokens work only with the broker's in-memory key" };
    if (declared.dpop === "supported") return { status: "available", detail: "provider supports DPoP: set connection.auth.dpop: true" };
    if (declared.dpop === "unsupported") return { status: "unsupported", detail: "provider doesn't support DPoP: tokens are short-lived but unbound" };
    return { status: "unknown", detail: "declare capabilities.dpop (supported / unsupported)" };
  };
  const ipAllowlist = (): Capability => {
    if (noCred) return na("public source: no credential");
    const allow = conn.credential?.provider_ip_allowlist;
    if (allow) return { status: "enforced", detail: `by the provider: ${allow.join(", ")} (hub egress checked on the posture card)` };
    if (conn.credential?.provider_ip_restriction === "yes") return { status: "enforced", detail: "by the provider (ranges not declared)" };
    if (declared.ip_allowlist === "supported") return { status: "available", detail: "provider supports IP allow-lists: set one, then declare credential.provider_ip_allowlist" };
    if (declared.ip_allowlist === "unsupported" || conn.credential?.provider_ip_restriction === "no")
      return { status: "unsupported", detail: "provider can't restrict this credential by IP: rely on detection, short lifetimes and rotation" };
    return { status: "unknown", detail: "declare capabilities.ip_allowlist (supported / unsupported)" };
  };
  const foreignIp = (): Capability => {
    if (detectRules) return { status: "monitored", detail: `${detectRules} detect rule(s) on this connector's audit-log stream` };
    if (noCred) return na("public source: no credential to watch");
    if (declared.audit_log === "available") return { status: "available", detail: "provider has an audit log: add a connector for it with a detect rule" };
    if (declared.audit_log === "ingested") return { status: "monitored", detail: "watched by another connector's detect rule" };
    if (declared.audit_log === "unavailable") return { status: "unsupported", detail: "provider exposes no audit log" };
    return { status: "unknown", detail: "declare capabilities.audit_log (ingested / available / unavailable)" };
  };
  const revocation = (): Capability => {
    if (noCred) return na("public source: nothing to revoke");
    if (a.type === "oauth2_client_credentials" && a.revocation_url) return { status: "enforced", detail: "kill switch revokes tokens at the provider (RFC 7009)" };
    return { status: "monitored", detail: "manual: the kill switch prints a revocation checklist" };
  };
  const rotation = (): Capability => {
    if (noCred) return na("public source: no credential");
    const max = conn.credential?.max_age_days;
    return max ? { status: "monitored", detail: `alert when older than ${max} days; idle auto-disable ${conn.credential?.idle_disable_days ?? "off"}` } : { status: "unknown", detail: "set credential.max_age_days" };
  };

  return {
    credential_broker: noCred ? na("public source: no credential") : { status: "enforced", detail: "only the broker holds and uses the secret" },
    egress_policy: { status: "enforced", detail: `broker allows only ${conn.policy.allowed_hosts.join(", ")}, declared paths, read-only methods` },
    staged_integrity: { status: "enforced", detail: "staged; published only when verified; every run has a receipt" },
    token_binding: tokenBinding(),
    ip_allowlist: ipAllowlist(),
    foreign_ip_detection: foreignIp(),
    revocation: revocation(),
    rotation_hygiene: rotation(),
  };
}

/** The registry: every connector x every control. Unreadable configs are reported, not hidden. */
export async function capabilityMatrix(
  ids: string[],
  load: (id: string) => Promise<ResolvedConnector>,
): Promise<{ controls: readonly Control[]; connectors: { id: string; source?: string; error?: string; capabilities?: Capabilities }[] }> {
  const connectors = [];
  for (const id of ids) {
    try {
      const c = await load(id);
      connectors.push({ id, source: c.metadata.source, capabilities: capabilitiesOf(c) });
    } catch (e) {
      connectors.push({ id, error: (e as Error).message });
    }
  }
  return { controls: CONTROLS, connectors };
}
