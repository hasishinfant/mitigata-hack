import { describe, expect, it } from "vitest";
import type { FieldSpec } from "../src/config/schema.ts";
import { mapRecord } from "../src/mapping/mapper.ts";
import { applyTransform, cvssToSeverity, toIso } from "../src/mapping/transforms.ts";

const user = {
  id: "00u1",
  status: "SUSPENDED",
  lastLogin: "2026-03-04T05:06:07.000Z",
  profile: { firstName: "Ada", lastName: "Lovelace", email: "Ada@Example.COM" },
  groups: [{ name: "admins" }, { name: "eng" }],
};
const userMap: Record<string, FieldSpec> = {
  id: { path: "id", required: true },
  name: { concat: ["profile.firstName", { lit: " " }, "profile.lastName"] },
  email: { path: "profile.email", transform: "lowercase", required: true },
  status: { path: "status", map_enum: { ACTIVE: "active", SUSPENDED: "suspended" }, default: "unknown" },
  last_login: { path: "lastLogin", transform: "to_iso8601" },
  attributes: { pick: ["groups[*].name", "profile.firstName", "nope"] },
};

describe("mapper", () => {
  it("rename, nested, concat, map_enum, dates, pick", () => {
    const r = mapRecord(user, "user", userMap);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.record).toEqual({
      sourceId: "00u1",
      fields: { name: "Ada Lovelace", email: "ada@example.com", status: "suspended", last_login: "2026-03-04T05:06:07.000Z" },
      attributes: { "groups[*].name": ["admins", "eng"], "profile.firstName": "Ada" },
    });
  });
  it("unmapped enum value falls back to default; concat with one part missing", () => {
    const r = mapRecord({ ...user, status: "WEIRD", profile: { firstName: "Ada", email: "a@b.c" } }, "user", userMap);
    expect(r.ok && r.record.fields).toMatchObject({ status: "unknown", name: "Ada" });
  });
  it("required field missing -> errors, not a throw", () => {
    const r = mapRecord({ id: "x", profile: {} }, "user", userMap);
    expect(r.ok).toBe(false);
    expect(!r.ok && r.errors[0]).toContain("email: required value missing (path profile.email)");
  });
  it("id and event type are always required", () => {
    const r = mapRecord({}, "event", { id: { path: "id" }, type: { path: "t" } });
    expect(!r.ok && r.errors).toHaveLength(2);
  });
  it("path list: first non-empty wins", () => {
    const m: Record<string, FieldSpec> = { id: { const: "1" }, type: { const: "v" }, severity: { path: ["a.v4", "a.v3", "a.v2"], transform: "cvss_to_severity" } };
    const r = mapRecord({ a: { v3: 9.8, v2: 5 } }, "event", m);
    expect(r.ok && r.record.fields.severity).toBe("critical");
  });
  it("severity outside enum and bad ip are quarantined", () => {
    expect(mapRecord({}, "event", { id: { const: 1 }, type: { const: "x" }, severity: { const: "severe" } }).ok).toBe(false);
    expect(mapRecord({ ip: "999.1.1.1" }, "device", { id: { const: 1 }, ip: { path: "ip" } }).ok).toBe(false);
    expect(mapRecord({ ip: "10.0.0.1" }, "device", { id: { const: 1 }, ip: { path: "ip" } }).ok).toBe(true);
  });
  it("array into a scalar field is an error unless `first`", () => {
    expect(mapRecord(user, "event", { id: { const: 1 }, type: { path: "groups[*].name" } }).ok).toBe(false);
    const r = mapRecord(user, "event", { id: { const: 1 }, type: { path: "groups[*].name", transform: "first" } });
    expect(r.ok && r.record.fields.type).toBe("admins");
  });
  it("bad date is a mapping error", () => {
    const r = mapRecord({ id: 1, d: "not a date" }, "user", { id: { path: "id" }, last_login: { path: "d" } });
    expect(!r.ok && r.errors[0]).toContain("not a valid date");
  });
});

describe("transforms", () => {
  it("dates are UTC", () => {
    expect(toIso("2024-01-15")).toBe("2024-01-15T00:00:00.000Z");
    expect(toIso("2024-01-15T10:00:00.000")).toBe("2024-01-15T10:00:00.000Z"); // NVD style, no tz
    expect(toIso("2024-01-15T10:00:00.000+0530")).toBe("2024-01-15T04:30:00.000Z");
    expect(toIso(1700000000)).toBe("2023-11-14T22:13:20.000Z");
    expect(toIso(1700000000000)).toBe("2023-11-14T22:13:20.000Z");
    expect(applyTransform("from_epoch_ms", "1700000000000")).toBe("2023-11-14T22:13:20.000Z");
    expect(applyTransform("from_epoch_s", 1700000000)).toBe("2023-11-14T22:13:20.000Z");
  });
  it("cvss buckets", () => {
    expect([0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10].map(cvssToSeverity)).toEqual(
      ["info", "low", "low", "medium", "medium", "high", "high", "critical", "critical"]);
    expect(() => cvssToSeverity(11)).toThrow();
  });
  it("misc", () => {
    expect(applyTransform("to_number", "42")).toBe(42);
    expect(() => applyTransform("to_number", "x")).toThrow();
    expect(applyTransform("trim", "  a ")).toBe("a");
    expect(applyTransform("uppercase", ["a", "b"])).toEqual(["A", "B"]);
    expect(applyTransform("first", [null, "x"])).toBe("x");
  });
});
