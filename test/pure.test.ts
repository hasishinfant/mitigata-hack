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

describe("schema fingerprint and integrity evaluator", () => {
  it("fingerprint: recursive paths and types; additive changes are fine, mapped removals and type changes break", async () => {
    const { ShapeCollector, diffSchema, mappedPointers, pointerOf } = await import("../src/engine/fingerprint.ts");
    const shape = (recs: unknown[]) => {
      const c = new ShapeCollector();
      recs.forEach((r) => c.add(r));
      return c.result();
    };
    const base = shape([{ id: "1", cve: { metrics: [{ score: 9.1 }] }, _source: { "kibana.alert.severity": "high" } }]);
    expect(Object.keys(base.shape)).toEqual(["/_source", "/_source/kibana.alert.severity", "/cve", "/cve/metrics", "/cve/metrics/[]", "/cve/metrics/[]/score", "/id"]);
    expect(pointerOf('_source["kibana.alert.severity"]')).toBe("/_source/kibana.alert.severity");
    expect(pointerOf("cve.metrics[0].score")).toBe("/cve/metrics/[]/score");
    const mapping = { id: { path: "id" }, severity: { path: ['_source["kibana.alert.severity"]', "sev"] }, description: { path: "cve.metrics[0].score" } };
    expect(mappedPointers(mapping)).toEqual(["/_source/kibana.alert.severity", "/cve/metrics/[]/score", "/id", "/sev"]);

    const added = shape([{ id: "1", cve: { metrics: [{ score: 9.1 }] }, _source: { "kibana.alert.severity": "high" }, extra: true }]);
    expect(diffSchema(base.shape, added.shape, mapping)).toEqual({ breaking: [], added: 1, removed: 0 });
    expect(added.fingerprint).not.toBe(base.fingerprint);
    const broke = shape([{ id: 1, cve: { metrics: [] } }]);
    expect(diffSchema(base.shape, broke.shape, mapping).breaking).toEqual([
      "id: /id changed type string -> number",
      'severity: /_source/kibana.alert.severity | /sev no longer present',
      "description: /cve/metrics/[]/score no longer present",
    ]);
    // A field that only becomes null sometimes is not a type change.
    expect(diffSchema(base.shape, shape([{ id: null }, { id: "2" }]).shape, { id: { path: "id" } }).breaking).toEqual([]);
  });

  it("evaluator: complete + clean = verified; caps and resumable failures = incomplete; loops = rejected; limits = held", async () => {
    const { evaluateIntegrity } = await import("../src/engine/integrity.ts");
    type Input = Parameters<typeof evaluateIntegrity>[0];
    const base: Input = { status: "success", completed: true, resumable: false, lockLost: false, seen: 10, accepted: 10, quarantined: 0, drift: [], schemaBreaking: [], maxQuarantineRatio: 0.1, minRecords: 0 };
    const d = (o: Partial<Input>) => evaluateIntegrity({ ...base, ...o });
    expect(d({})).toMatchObject({ decision: "verified", publish: true, discard: false });
    expect(d({ seen: 0, accepted: 0 })).toMatchObject({ decision: "verified_empty", publish: true });
    expect(d({ status: "partial", stopReason: "stopped at policy.max_requests_per_run (2)", completed: false })).toMatchObject({ decision: "incomplete", publish: false, discard: false });
    expect(d({ status: "failed", completed: false, resumable: true, lastError: "network" })).toMatchObject({ decision: "incomplete" });
    expect(d({ status: "failed", completed: false, resumable: false, lastError: "pagination incomplete" })).toMatchObject({ decision: "rejected", discard: true });
    expect(d({ quarantined: 2, accepted: 8 })).toMatchObject({ decision: "held", reasons: ["2 of 10 records quarantined (20% > 10% allowed)"] });
    expect(d({ quarantined: 1, accepted: 9 })).toMatchObject({ decision: "verified" });
    expect(d({ schemaBreaking: ["x: /x no longer present"] })).toMatchObject({ decision: "held" });
    expect(d({ minRecords: 11 })).toMatchObject({ decision: "held" });
    expect(d({ lockLost: true, status: "failed" })).toMatchObject({ decision: "incomplete", publish: false, discard: false });
  });

  it("receipt digest is over canonical JSON: key order doesn't matter, content does", async () => {
    const { receiptDigest } = await import("../src/engine/receipt.ts");
    expect(receiptDigest({ a: 1, b: { c: [1, 2], d: "x" } })).toBe(receiptDigest({ b: { d: "x", c: [1, 2] }, a: 1 }));
    expect(receiptDigest({ a: 1 })).not.toBe(receiptDigest({ a: 2 }));
  });
});
