import { describe, expect, it } from "vitest";
import { pathAllowed, hostAllowed } from "../src/broker/policy.ts";
import { parsePath, resolvePath } from "../src/mapping/paths.ts";
import { findSecrets, redactValue } from "../src/mapping/scanner.ts";

describe("paths", () => {
  const doc = { a: { b: { c: 1 } }, list: [{ x: 1 }, { x: 2 }, {}], "odd key": 5 };
  it("resolves", () => {
    expect(resolvePath(doc, "a.b.c")).toBe(1);
    expect(resolvePath(doc, "$")).toBe(doc);
    expect(resolvePath(doc, "list[1].x")).toBe(2);
    expect(resolvePath(doc, "list[*].x")).toEqual([1, 2]);
    expect(resolvePath(doc, '["odd key"]')).toBe(5);
    expect(resolvePath(doc, "a.nope.c")).toBeUndefined();
    expect(resolvePath({}, "constructor")).toBeUndefined();
  });
  it("rejects bad syntax and depth > 10", () => {
    for (const bad of ["", "a..b", "a.", "a[x]", "a[", ".a", "a b", "a.b.c.d.e.f.g.h.i.j.k"]) expect(() => parsePath(bad)).toThrow();
  });
});

describe("policy matchers", () => {
  it("hosts", () => {
    expect(hostAllowed("api.github.com", ["api.github.com"])).toBe(true);
    expect(hostAllowed("api.github.com.evil.io", ["api.github.com"])).toBe(false);
    expect(hostAllowed("a.b.okta.com", ["*.okta.com"])).toBe(false);
  });
  it("paths", () => {
    expect(pathAllowed("/orgs/acme/members", ["/orgs/*/members"])).toBe(true);
    expect(pathAllowed("/api/v1/users/1/lifecycle/deactivate", ["/api/v1/users"])).toBe(false);
    expect(pathAllowed("/api/v1/../admin", ["/api/**"])).toBe(false);
  });
});

describe("secret scanner", () => {
  const seeded = {
    aws: "key AKIAIOSFODNN7EXAMPLE here",
    gh: "ghp_" + "a".repeat(36),
    pem: "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
    jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
    okta: "SSWS 00abcdefghijklmnopqrstuv",
  };
  it("catches seeded secrets", () => {
    const out = JSON.stringify(redactValue(seeded));
    for (const s of ["AKIA", "ghp_", "BEGIN RSA", "eyJ", "SSWS 00"]) expect(out).not.toContain(s);
    expect(out).toContain("[REDACTED:aws_access_key]");
  });
  it("no false positive on UUIDs", () => {
    expect(findSecrets("00u1a2b3-c4d5-4e6f-8a9b-0c1d2e3f4a5b 550e8400-e29b-41d4-a716-446655440000")).toEqual([]);
  });
});

describe("bounded denial log", () => {
  it("writes a summary only when something was suppressed; counts stay exact", async () => {
    const { DenialLog } = await import("../src/broker/limits.ts");
    const rows: { records?: number | null; decision: string }[] = [];
    let t = 0;
    const log = new DenialLog(async (e) => void rows.push({ records: e.records, decision: e.decision }), 60_000, () => t);
    const d = { action: "admin", decision: "deny: x" };
    await log.record("k", d); // window 1: one denial, nothing suppressed
    t += 61_000;
    await log.record("k", d); // window 2: no summary for window 1
    await log.record("k", d);
    await log.record("k", d); // two suppressed
    t += 61_000;
    await log.record("k", d); // window 3: summary for window 2 first
    await log.close();
    expect(rows).toEqual([
      { records: 1, decision: "deny: x" },
      { records: 1, decision: "deny: x" },
      { records: 2, decision: "deny: x (and 2 more within 60 s, summarised)" },
      { records: 1, decision: "deny: x" },
    ]);
    expect(rows.every((r) => (r.records ?? 0) > 0)).toBe(true);
    expect(rows.reduce((n, r) => n + (r.records ?? 0), 0)).toBe(5);
  });
});
