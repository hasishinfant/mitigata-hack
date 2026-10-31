// Phase 2 gate: mock GitHub and NVD (plus Okta-like and Jira-like) sync into users and events.
import { readdirSync, readFileSync, statSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createLocalBroker } from "../src/broker/client.ts";
import { envSecretSource } from "../src/broker/secrets.ts";
import { BrokerError } from "../src/broker/types.ts";
import { runConnector } from "../src/engine/runner.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector, registerConnector } from "../src/store/connectors.ts";
import { queryRecords } from "../src/store/query.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { buildMock, MOCK_TOKENS, type Mock } from "../mock/server.ts";
import { clearData, hasDb, testUrl } from "./helpers/db.ts";

const fixture = (name: string) => readFileSync(join(import.meta.dirname, "fixtures/configs", name), "utf8");
const goodSecrets = {
  IX_SECRET_MOCK_BEARER: MOCK_TOKENS.bearer,
  IX_SECRET_MOCK_API_KEY: MOCK_TOKENS.apiKey,
  IX_SECRET_MOCK_SSWS: MOCK_TOKENS.ssws,
  IX_SECRET_MOCK_BASIC_USER: MOCK_TOKENS.basicUser,
  IX_SECRET_MOCK_BASIC_PASS: MOCK_TOKENS.basicPass,
};

describe.skipIf(!hasDb)("engine on mocks", () => {
  let mock: Mock;
  let pool: Pool;
  let env: Record<string, string | undefined>;

  beforeAll(async () => {
    mock = buildMock({ cveMissingIdAt: [17] });
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
  });

  async function sync(file: string, secrets: Record<string, string> = goodSecrets) {
    const r = await registerConnector(pool, fixture(file), { env });
    const conn = await loadActiveConnector(pool, r.id, env);
    const broker = createLocalBroker({ getConnector: (id) => (id === conn.metadata.id ? conn : undefined), secrets: envSecretSource(secrets) });
    const [summary] = await runConnector({ connector: conn, broker, store: createPgRunStore(pool) });
    return { summary: summary!, conn, broker };
  }

  it("GitHub-like members (bearer, Link header) -> users", async () => {
    const { summary } = await sync("mock-github-members.yaml");
    expect(summary).toMatchObject({ status: "success", requests: 3, recordsOk: 250, recordsQuarantined: 0 });
    const { total, rows } = await queryRecords(pool, "user", { source: "github", limit: 1 });
    expect(total).toBe(250);
    expect(rows[0]).toMatchObject({ id: "1001", name: "dev1", status: "active", source: "github" });
    const run = (await pool.query("select status, requests, records_ok, finished_at from runs")).rows[0];
    expect(run).toMatchObject({ status: "success", requests: 3, records_ok: 250 });
    expect(run.finished_at).toBeTruthy();
  });

  it("NVD-like CVEs (api key, offset): exactly 3 calls, bad record quarantined, run partial", async () => {
    const { summary } = await sync("mock-nvd-cves.yaml");
    expect(mock.calls.filter((c) => c.path === "/rest/json/cves/2.0").map((c) => c.query.startIndex)).toEqual(["0", "2000", "4000"]);
    expect(summary).toMatchObject({ status: "partial", requests: 3, recordsOk: 4499, recordsQuarantined: 1 });
    const { total } = await queryRecords(pool, "event", { source: "nvd" });
    expect(total).toBe(4499);
    const row = (await pool.query("select severity, ts, description, attributes from events where source_id = 'CVE-2026-10000'")).rows[0];
    expect(row.ts).toBe("2026-01-01T01:00:00.000Z"); // timezone-less NVD timestamp stored as UTC
    expect(row.severity).toBe("info"); // score 0.0
    expect(row.attributes["cve.vulnStatus"]).toBe("Analyzed");
    const sev = (await pool.query("select distinct severity from events order by 1")).rows.map((r) => r.severity);
    expect(sev).toEqual(["critical", "high", "info", "low", "medium"]);
    const q = (await pool.query("select errors, raw_redacted from quarantine")).rows;
    expect(q).toHaveLength(1);
    expect(q[0].errors[0]).toContain("id: required value missing");
  });

  it("re-running never duplicates rows", async () => {
    await sync("mock-github-members.yaml");
    await sync("mock-github-members.yaml");
    expect((await queryRecords(pool, "user", { source: "github" })).total).toBe(250);
    expect(Number((await pool.query("select count(*) from runs")).rows[0].count)).toBe(2);
  });

  it("Okta-like users (SSWS api key, Link cursor) land next to GitHub users in one table", async () => {
    await sync("mock-github-members.yaml");
    const { summary } = await sync("mock-okta-users.yaml");
    expect(summary).toMatchObject({ status: "success", requests: 3, recordsOk: 450 });
    const r = (await pool.query("select email, status, name, last_login from users where source = 'okta' and source_id = '00u000002'")).rows[0];
    expect(r).toEqual({ email: "user2@example.test", status: "suspended", name: "First2 Last2", last_login: "2026-01-01T02:00:00.000Z" });
    const bySource = (await pool.query("select source, count(*)::int as n from users group by source order by source")).rows;
    expect(bySource).toEqual([{ source: "github", n: 250 }, { source: "okta", n: 450 }]);
  });

  it("Jira-like tickets (basic auth, body cursor + isLast) -> events", async () => {
    const { summary } = await sync("mock-jira-issues.yaml");
    expect(summary).toMatchObject({ status: "success", requests: 3, recordsOk: 120 });
    const r = (await pool.query("select severity, description, ts from events where source_id = '20004'")).rows[0];
    expect(r).toEqual({ severity: "critical", description: "SEC-5: Mock ticket 5", ts: "2026-01-01T04:00:00.000Z" });
  });

  it("wrong key -> auth_failed after one request, secret not echoed", async () => {
    const bad = { ...goodSecrets, IX_SECRET_MOCK_BEARER: "wrong-token-value-000" };
    const { summary } = await sync("mock-github-members.yaml", bad);
    expect(summary).toMatchObject({ status: "auth_failed", requests: 1, recordsOk: 0 });
    expect(summary.lastError).toBe("HTTP 401: credentials rejected");
    const run = (await pool.query("select status, requests from runs")).rows[0];
    expect(run).toEqual({ status: "auth_failed", requests: 1 });
  });

  it("missing secret -> auth_failed with the ref name only", async () => {
    const { IX_SECRET_MOCK_API_KEY: _drop, ...rest } = goodSecrets;
    const { summary } = await sync("mock-nvd-cves.yaml", rest);
    expect(summary.status).toBe("auth_failed");
    expect(summary.lastError).toContain('secret "mock_api_key" is not set');
  });

  it("broker denies hosts and paths outside policy, without calling out", async () => {
    const { conn, broker } = await sync("mock-github-members.yaml");
    const before = mock.calls.length;
    const port = env.MOCK_PORT;
    for (const url of [
      `http://evil.test:${port}/orgs/acme/members`,
      `http://localhost:${port}/rest/json/cves/2.0`,
      `http://localhost:${port}/orgs/acme/members/../../admin`,
    ]) {
      await expect(broker.request({ connectorId: conn.metadata.id, method: "GET", url })).rejects.toSatisfy(
        (e) => e instanceof BrokerError && e.kind === "policy_denied",
      );
    }
    await expect(
      broker.request({ connectorId: conn.metadata.id, method: "GET", url: `http://localhost:${port}/orgs/acme/members`, headers: { Authorization: "x" } }),
    ).rejects.toThrow(/may not be set by workers/);
    expect(mock.calls.length).toBe(before);
  });

  it("no secret value anywhere in the database after syncs", async () => {
    await sync("mock-github-members.yaml");
    await sync("mock-nvd-cves.yaml");
    await sync("mock-okta-users.yaml");
    await sync("mock-jira-issues.yaml");
    await sync("mock-github-members.yaml", { ...goodSecrets, IX_SECRET_MOCK_BEARER: "wrong-token-value-000" });
    const dump = JSON.stringify(
      await Promise.all(
        ["runs", "quarantine", "connector_versions", "users", "events"].map(async (t) => (await pool.query(`select * from ${t}`)).rows),
      ),
    );
    for (const secret of [...Object.values(goodSecrets).filter((s) => s.length >= 8), "wrong-token-value-000"]) expect(dump).not.toContain(secret);
  });
});

describe("config-driven guarantee", () => {
  it("engine and broker contain no provider names", () => {
    const hits: string[] = [];
    const walk = (dir: string) => {
      for (const f of readdirSync(dir)) {
        const p = join(dir, f);
        if (statSync(p).isDirectory()) walk(p);
        else if (/github|okta|nvd|cisa/i.test(readFileSync(p, "utf8"))) hits.push(p);
      }
    };
    walk(join(import.meta.dirname, "../src/engine"));
    walk(join(import.meta.dirname, "../src/broker"));
    expect(hits).toEqual([]);
  });
});
