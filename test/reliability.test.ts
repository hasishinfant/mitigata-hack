// Phase 3 gate: the PRD failure tests (wrong key, network drop mid-run, 429, missing fields)
// plus timeouts, 5xx retries, circuit breaker and schema drift. Fake clock: nothing really sleeps.
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createLocalBroker } from "../src/broker/client.ts";
import { envSecretSource } from "../src/broker/secrets.ts";
import { runConnector } from "../src/engine/runner.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector, registerConnector } from "../src/store/connectors.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { buildMock, MOCK_TOKENS, type Mock } from "../mock/server.ts";
import { fakeClock } from "./helpers/clock.ts";
import { clearData, hasDb, regPool, testUrl } from "./helpers/db.ts";

const DEFAULT_RELIABILITY = "reliability: { rate_limit: { requests_per_minute: 600 } }";
const fixture = (name: string, reliability?: string) => {
  const text = readFileSync(join(import.meta.dirname, "fixtures/configs", name), "utf8");
  return reliability ? text.replace(DEFAULT_RELIABILITY, `reliability: ${reliability}`) : text;
};
const secrets = {
  IX_SECRET_MOCK_BEARER: MOCK_TOKENS.bearer,
  IX_SECRET_MOCK_API_KEY: MOCK_TOKENS.apiKey,
  IX_SECRET_MOCK_SSWS: MOCK_TOKENS.ssws,
};
const NVD = "/rest/json/cves/2.0";

describe.skipIf(!hasDb)("reliability", () => {
  let mock: Mock;
  let pool: Pool;
  let env: Record<string, string | undefined>;
  let fc: ReturnType<typeof fakeClock>;

  beforeAll(async () => {
    mock = buildMock();
    await mock.app.listen({ host: "127.0.0.1", port: 0 });
    env = { ...process.env, MOCK_PORT: String((mock.app.server.address() as AddressInfo).port) };
    pool = createPool(testUrl("DATABASE_URL_APP"));
  });
  afterAll(async () => {
    await pool?.end();
    await mock?.app.close();
  });
  beforeEach(async () => {
    await clearData(pool);
    mock.calls.length = 0;
    mock.setFault(null);
    mock.options.cveMissingIdAt = [];
    mock.options.renameEmail = false;
    fc = fakeClock();
  });

  async function register(text: string) {
    return (await registerConnector(regPool(), text, { env })).id;
  }
  async function run(id: string, s: Record<string, string> = secrets) {
    const conn = await loadActiveConnector(pool, id, env);
    const broker = createLocalBroker({
      getConnector: (cid) => (cid === conn.metadata.id ? conn : undefined),
      secrets: envSecretSource(s),
      clock: fc.clock,
      random: () => 0.5, // jitter centred: waits are exactly 1 s, 2 s, 4 s
    });
    const [summary] = await runConnector({ connector: conn, broker, store: createPgRunStore(pool) });
    return summary!;
  }
  const startIndexes = () => mock.calls.filter((c) => c.path === NVD).map((c) => c.query.startIndex);
  const count = async (sql: string) => Number((await pool.query(sql)).rows[0].count);

  // ---------- PRD failure test 1: wrong or expired key ----------
  it("wrong key: one attempt, auth_failed, alert raised, no retry", async () => {
    const id = await register(fixture("mock-nvd-cves.yaml"));
    const s = await run(id, { ...secrets, IX_SECRET_MOCK_API_KEY: "expired-key-00000" });
    expect(s).toMatchObject({ status: "auth_failed", requests: 1, retries: 0 });
    expect(startIndexes()).toEqual(["0"]);
    expect(fc.waits("backoff")).toEqual([]);
    expect((await pool.query("select kind from alerts")).rows).toEqual([{ kind: "auth_failed" }]);
  });

  // ---------- PRD failure test 2: network off mid-run ----------
  it("network drop mid-run: retries 1/2/4 s, fails, keeps checkpoint, next run resumes", async () => {
    const id = await register(fixture("mock-nvd-cves.yaml"));
    mock.setFault({ mode: "drop", path: NVD, after: 1, count: 100 });
    const s1 = await run(id);
    expect(s1.status).toBe("failed");
    expect(s1.lastError).toMatch(/network.*after 3 retries/);
    expect(fc.waits("backoff")).toEqual([1000, 2000, 4000]);
    expect(s1).toMatchObject({ requests: 2, recordsOk: 2000, retries: 3 });
    const cp = (await pool.query("select page_state from checkpoints")).rows[0].page_state;
    expect(new URL(cp.next_url).searchParams.get("startIndex")).toBe("2000");
    expect(await count("select count(*) from events")).toBe(2000);

    mock.setFault(null);
    mock.calls.length = 0;
    const s2 = await run(id);
    expect(s2).toMatchObject({ status: "success", resumed: true, requests: 2, recordsOk: 2500 });
    expect(startIndexes()).toEqual(["2000", "4000"]);
    expect(await count("select count(*) from events")).toBe(4500);
    expect(await count("select count(*) from checkpoints")).toBe(0);
  });

  // ---------- PRD failure test 3: calling faster than the limit (429) ----------
  it("429 with Retry-After: 30 waits 30 s, retries the same page, no duplicates", async () => {
    const id = await register(fixture("mock-nvd-cves.yaml"));
    mock.setFault({ mode: "429", path: NVD, after: 1, count: 1, retryAfter: "30" });
    const s = await run(id);
    expect(s).toMatchObject({ status: "success", requests: 3, recordsOk: 4500, retries: 1, rateLimitedMs: 30_000 });
    expect(fc.waits("rate_limit")).toEqual([30_000]);
    expect(startIndexes()).toEqual(["0", "2000", "2000", "4000"]);
    expect(await count("select count(*) from events")).toBe(4500);
    expect((await pool.query("select retries, rate_limited_ms from runs")).rows[0]).toEqual({ retries: 1, rate_limited_ms: 30_000 });
  });

  it("429 with Retry-After as an HTTP date", async () => {
    const id = await register(fixture("mock-nvd-cves.yaml"));
    mock.setFault({ mode: "429", path: NVD, count: 1, retryAfter: new Date(Date.now() + 10_000).toUTCString() });
    expect((await run(id)).status).toBe("success");
    const [w] = fc.waits("rate_limit");
    expect(w).toBeGreaterThan(8_000);
    expect(w).toBeLessThanOrEqual(10_000);
  });

  it("429 asking for longer than max_wait fails with a clear reason", async () => {
    const id = await register(fixture("mock-nvd-cves.yaml", "{ rate_limit: { requests_per_minute: 600, max_wait: 60s } }"));
    mock.setFault({ mode: "429", path: NVD, count: 1, retryAfter: "300" });
    const s = await run(id);
    expect(s.status).toBe("failed");
    expect(s.lastError).toBe("rate_limited: provider asked to wait 300 s, more than max_wait 60 s");
    expect(fc.waits("rate_limit")).toEqual([]);
  });

  it("429 without Retry-After falls back to backoff", async () => {
    const id = await register(fixture("mock-nvd-cves.yaml"));
    mock.setFault({ mode: "429", path: NVD, count: 2 });
    expect((await run(id)).status).toBe("success");
    expect(fc.waits("rate_limit")).toEqual([1000, 2000]);
  });

  it("GitHub-style 403 with x-ratelimit-remaining: 0 waits until reset", async () => {
    const id = await register(fixture("mock-github-members.yaml"));
    mock.setFault({ mode: "ratelimit403", path: "/orgs", after: 1, count: 1, resetInSec: 5 });
    const s = await run(id);
    expect(s).toMatchObject({ status: "success", recordsOk: 250 });
    const [w] = fc.waits("rate_limit");
    expect(w).toBeGreaterThan(3_000);
    expect(w).toBeLessThanOrEqual(6_000);
  });

  // ---------- PRD failure test 4: record with missing fields ----------
  it("record with missing required field is quarantined; run is partial and completes", async () => {
    mock.options.cveMissingIdAt = [5, 2500];
    const id = await register(fixture("mock-nvd-cves.yaml"));
    const s = await run(id);
    expect(s).toMatchObject({ status: "partial", recordsOk: 4498, recordsQuarantined: 2, lastError: "2 record(s) quarantined" });
    const q = (await pool.query("select errors, raw_redacted from quarantine order by id")).rows;
    expect(q[0].errors).toEqual(["id: required value missing (path cve.id)"]);
    expect(q[0].raw_redacted.cve.descriptions[0].value).toBe("Mock vulnerability number 5");
  });

  // ---------- other reliability behaviour ----------
  it("transient 503s are retried with backoff, then succeed", async () => {
    const id = await register(fixture("mock-nvd-cves.yaml"));
    mock.setFault({ mode: "503", path: NVD, after: 2, count: 2 });
    const s = await run(id);
    expect(s).toMatchObject({ status: "success", retries: 2, recordsOk: 4500 });
    expect(fc.waits("backoff")).toEqual([1000, 2000]);
    expect(startIndexes()).toEqual(["0", "2000", "4000", "4000", "4000"]);
  });

  it("timeouts are retried", async () => {
    const id = await register(fixture("mock-nvd-cves.yaml", "{ timeout: 300ms, rate_limit: { requests_per_minute: 600 } }"));
    mock.setFault({ mode: "timeout", path: NVD, count: 1, delayMs: 2000 });
    const s = await run(id);
    expect(s).toMatchObject({ status: "success", retries: 1 });
    expect(fc.waits("backoff")).toEqual([1000]);
  });

  it("503 storm: run fails after 3 retries, breaker opens after N failed runs, then half-opens after cool-down", async () => {
    const id = await register(
      fixture("mock-nvd-cves.yaml", "{ rate_limit: { requests_per_minute: 600 }, circuit_breaker: { failures_to_open: 2, cool_down: 10m } }"),
    );
    mock.setFault({ mode: "503", path: NVD, count: 1000 });
    const s1 = await run(id);
    expect(s1.status).toBe("failed");
    expect(s1.lastError).toMatch(/^HTTP 503 after 3 retries/);
    expect((await pool.query("select status from connectors")).rows[0].status).toBe("enabled");

    await run(id);
    const c = (await pool.query("select status, paused_until, disabled_reason from connectors")).rows[0];
    expect(c.status).toBe("paused");
    expect(new Date(c.paused_until).getTime()).toBeGreaterThan(Date.now() + 9 * 60_000);
    expect(c.disabled_reason).toMatch(/circuit open after 2 consecutive failures/);
    expect((await pool.query("select kind from alerts where kind = 'circuit_open'")).rowCount).toBe(1);

    mock.calls.length = 0;
    const s3 = await run(id);
    expect(s3.status).toBe("paused");
    expect(mock.calls).toHaveLength(0); // no calls while open

    mock.setFault(null);
    await pool.query("update connectors set paused_until = now() - interval '1 second'");
    const s4 = await run(id);
    expect(s4.status).toBe("success");
    expect((await pool.query("select status from connectors")).rows[0].status).toBe("enabled");
  });

  it("schema drift: provider renames a field -> run is degraded and alerts", async () => {
    const id = await register(fixture("mock-okta-users.yaml"));
    expect((await run(id)).status).toBe("success");
    mock.options.renameEmail = true;
    const s = await run(id);
    expect(s.status).toBe("degraded");
    expect(s.lastError).toBe("schema drift: email missing in 100% of records (was 0%)");
    expect((await pool.query("select kind from alerts")).rows).toEqual([{ kind: "degraded" }]);
    // Baseline stays the last good run, so the next drifted run is still flagged.
    expect((await run(id)).status).toBe("degraded");
  });

  it("a failed run never duplicates rows when retried from scratch or resumed", async () => {
    const id = await register(fixture("mock-github-members.yaml"));
    mock.setFault({ mode: "drop", path: "/orgs", after: 2, count: 100 });
    expect((await run(id)).status).toBe("failed");
    mock.setFault(null);
    expect((await run(id)).status).toBe("success");
    expect((await run(id)).status).toBe("success");
    expect(await count("select count(*) from users")).toBe(250);
  });
});
