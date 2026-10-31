import { describe, expect, it, vi } from "vitest";
import type { Pool } from "../src/store/db.ts";
import type { Posture } from "../src/security/posture.ts";
import { runRehearsal } from "../src/security/rehearsal.ts";

const posture = (id: string, risk: Posture["risk"]): Posture => ({
  connector_id: id,
  source: "example",
  status: "enabled",
  auth_type: "bearer",
  streams: [],
  reach: { allowed_hosts: ["api.example.com"], allowed_paths: ["/events"], read_only_post: [], methods: ["GET"], max_requests_per_run: 10, max_records_per_run: 100 },
  credentials: [{ ref: `${id}_token`, stored: true, age_days: 1, idle_days: 0, last_used_at: null, granted_scopes: null, scopes_seen_at: null }],
  scopes: { expected: [], granted: null, extra: [], missing: [], forbidden: [], writeLike: [], source: "unknown" },
  revocable_by_api: "unknown",
  provider_ip_restriction: "unknown",
  revoke_hint: null,
  limits: { max_age_days: null, idle_disable_days: null },
  data: { store_raw: false, retention_days: null },
  violations_7d: 0,
  last_violation: null,
  risk,
  flags: risk === "high" ? [{ level: "high", message: "over-privileged scope" }] : [],
});

function fakePool() {
  const statements: string[] = [];
  const pool = {
    query: async (sql: string) => {
      statements.push(sql);
      return { rows: [{ id: "okta", status: "enabled" }, { id: "old", status: "disabled" }] };
    },
  } as unknown as Pool;
  return { pool, statements };
}

describe("incident-response rehearsal", () => {
  it("reports readiness and a panic plan without issuing database mutations", async () => {
    const { pool, statements } = fakePool();
    const loadPosture = vi.fn(async (_pool: Pool, id: string) => posture(id, id === "okta" ? "high" : "low"));
    const checkLedger = vi.fn(async () => ({ ok: true, rows: 4 }));
    const broker = { ping: vi.fn(async () => true) };

    const report = await runRehearsal({ pool, broker, loadPosture, checkLedger });

    expect(report).toMatchObject({
      non_destructive: true,
      ready: true,
      checks: [
        { name: "broker", status: "pass" },
        { name: "audit ledger", status: "pass" },
        { name: "connector posture", status: "attention" },
        { name: "alert delivery", status: "not_tested" },
      ],
      panic_plan: {
        disable_connectors: ["okta"],
        cancel_queued_runs: true,
        clear_broker_token_cache: true,
        purge_stored_secrets: false,
      },
    });
    expect(report.connectors[0]).toMatchObject({ id: "okta", risk: "high", revocation: "manual_provider_revocation" });
    expect(statements).toHaveLength(1);
    expect(statements[0]!.trim().toLowerCase()).toMatch(/^select/);
    expect(broker.ping).toHaveBeenCalledOnce();
    expect(checkLedger).toHaveBeenCalledOnce();
  });

  it("marks the rehearsal not ready if the broker, ledger, or a connector posture is unavailable", async () => {
    const { pool } = fakePool();
    const loadPosture = vi.fn(async (_pool: Pool, id: string) => {
      if (id === "old") throw new Error("stored config no longer validates");
      return posture(id, "low");
    });

    const report = await runRehearsal({
      pool,
      broker: { ping: async () => false },
      loadPosture,
      checkLedger: async () => ({ ok: false, rows: 3, problem: "broken hash chain" }),
    });

    expect(report.ready).toBe(false);
    expect(report.checks.filter((c) => c.status === "fail")).toHaveLength(3);
    expect(report.connectors[1]).toMatchObject({ id: "old", revocation: "posture_unavailable", error: "stored config no longer validates" });
  });
});
