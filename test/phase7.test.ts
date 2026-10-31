// Phase 7: posture card + over-privileged detection, panic with revocation, idle auto-disable,
// consecutive-failure alerts delivered to Slack via the broker, incremental sync, raw-payload minimisation.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PgBoss } from "pg-boss";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApi } from "../src/api/server.ts";
import { createRemoteBroker, type RemoteBroker } from "../src/broker/remote.ts";
import { createBrokerServer, listenOnSocket } from "../src/broker/server.ts";
import { initialCursor, runConnector, type RunSummary } from "../src/engine/runner.ts";
import { deliverAlerts } from "../src/security/alerts.ts";
import { runHygiene } from "../src/security/hygiene.ts";
import { panic } from "../src/security/panic.ts";
import { deriveFlags, getPosture } from "../src/security/posture.ts";
import { assessScopes } from "../src/security/scopes.ts";
import { enqueueRun, RUN_QUEUE, startBoss } from "../src/scheduler/queue.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector, setConnectorEnabled } from "../src/store/connectors.ts";
import { getHealth } from "../src/store/health.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { buildMock, MOCK_TOKENS, type Mock } from "../mock/server.ts";
import { clearData, hasDb, testUrl } from "./helpers/db.ts";

const fixture = (name: string) => readFileSync(join(import.meta.dirname, "fixtures/configs", name), "utf8");
const DAY = 86_400_000;
const GH_CRED = "credential: { max_age_days: 90, idle_disable_days: 14 }";

describe("scope assessment and flags", () => {
  it("separates expected, extra, forbidden and write-like scopes", () => {
    const a = assessScopes(["read:org", "repo", "admin:org", "gist"], ["read:org", "members:read"], ["admin:*"]);
    expect(a).toMatchObject({ extra: ["repo", "admin:org", "gist"], missing: ["members:read"], forbidden: ["admin:org"], writeLike: ["repo", "admin:org"] });
    expect(assessScopes(null, ["x"]).granted).toBeNull();
  });
  it("initial cursor: relative or absolute", () => {
    const now = Date.parse("2026-10-31T00:00:00Z");
    expect(initialCursor("-7d", now)).toBe("2026-10-24T00:00:00.000Z");
    expect(initialCursor("-12h", now)).toBe("2026-10-30T12:00:00.000Z");
    expect(initialCursor("2026-01-01", now)).toBe("2026-01-01T00:00:00.000Z");
    expect(initialCursor(undefined, now)).toBeUndefined();
  });
  it("a no-auth connector with nothing odd is low risk", () => {
    const flags = deriveFlags({
      connector_id: "x", source: "s", status: "enabled", auth_type: "none", streams: [], credentials: [],
      reach: { allowed_hosts: [], allowed_paths: [], read_only_post: [], methods: ["GET"], max_requests_per_run: 1, max_records_per_run: 1 },
      scopes: { ...assessScopes(null), source: "unknown" }, revocable_by_api: false, provider_ip_restriction: "unknown", revoke_hint: null,
      limits: { max_age_days: null, idle_disable_days: null }, data: { store_raw: false, retention_days: null }, violations_7d: 0, last_violation: null,
    });
    expect(flags).toEqual([]);
  });
});

describe.skipIf(!hasDb)("breach features", () => {
  let mock: Mock;
  let appPool: Pool;
  let adminPool: Pool;
  let brokerPool: Pool;
  let server: ReturnType<typeof createBrokerServer>;
  let remote: RemoteBroker;
  let boss: PgBoss;
  let env: Record<string, string | undefined>;
  const socketPath = join(tmpdir(), `ixb7-${process.pid}.sock`);

  beforeAll(async () => {
    mock = buildMock();
    await mock.app.listen({ host: "127.0.0.1", port: 0 });
    env = { ...process.env, MOCK_PORT: String((mock.app.server.address() as AddressInfo).port) };
    appPool = createPool(testUrl("DATABASE_URL_APP"));
    adminPool = createPool(testUrl("DATABASE_URL_ADMIN"));
    brokerPool = createPool(testUrl("DATABASE_URL_BROKER"));
    server = createBrokerServer({ pool: brokerPool, masterKey: randomBytes(32), env, alertHosts: ["localhost"] });
    await listenOnSocket(server.app, socketPath);
    remote = createRemoteBroker(socketPath);
    boss = await startBoss(testUrl("DATABASE_URL_APP"));
  }, 60_000);
  afterAll(async () => {
    await boss?.stop({ graceful: false });
    await server?.app.close();
    await Promise.all([appPool?.end(), adminPool?.end(), brokerPool?.end()]);
    await mock?.app.close();
  });
  beforeEach(async () => {
    await clearData(appPool);
    await remote.forget();
    await boss.deleteAllJobs(RUN_QUEUE);
    mock.calls.length = 0;
    mock.slack.length = 0;
    mock.oauth.tokenCalls = 0;
    mock.oauth.revoked = 0;
    mock.options.githubScopes = "read:org";
    mock.options.touchedUsers = [];
  });

  const run = async (id: string): Promise<RunSummary> => {
    const conn = await loadActiveConnector(appPool, id, env);
    return (await runConnector({ connector: conn, broker: remote, store: createPgRunStore(appPool) }))[0]!;
  };
  const ghWith = (credential: string, extra = "") => fixture("mock-github-members.yaml").replace(GH_CRED, credential) + extra;

  it("posture: classic token with admin scopes is flagged HIGH risk (over-privileged badge)", async () => {
    mock.options.githubScopes = "repo, admin:org, read:org";
    await remote.register(
      ghWith('credential: { expected_scopes: ["read:org"], forbid_scopes: ["admin:*", "delete_repo"], scopes_header: X-OAuth-Scopes, max_age_days: 90, idle_disable_days: 14, provider_ip_restriction: "no", revoke_hint: "https://github.com/settings/tokens" }'),
      "add",
    );
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    expect((await run("mock-github-members")).status).toBe("success");

    const p = await getPosture(appPool, "mock-github-members", env);
    expect(p.scopes).toMatchObject({ granted: ["repo", "admin:org", "read:org"], forbidden: ["admin:org"], writeLike: ["repo", "admin:org"], source: "response_header" });
    expect(p.risk).toBe("high");
    expect(p.flags.slice(0, 2).map((f) => f.message)).toEqual([
      "forbidden scope granted: admin:org",
      "over-privileged: token can repo (connector only reads)",
    ]);
    expect(p.flags.map((f) => f.message)).toContain("token works from any IP: a stolen copy is usable anywhere");
    expect(p.credentials[0]).toMatchObject({ ref: "mock_bearer", stored: true, age_days: 0 });
    expect(p.reach.allowed_hosts).toEqual(["localhost"]);

    const h = await getHealth(appPool, env);
    expect(h.connectors[0]!.posture).toMatchObject({ risk: "high" });
  });

  it("posture counts policy violations from the ledger", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    const before = (await getPosture(appPool, "mock-github-members", env)).violations_7d; // ledger is shared across test files
    await expect(remote.request({ connectorId: "mock-github-members", method: "GET", url: "https://exfil.example/x" })).rejects.toThrow();
    const p = await getPosture(appPool, "mock-github-members", env);
    expect(p.violations_7d).toBe(before + 1);
    expect(p.last_violation!.decision).toBe("deny: host exfil.example not in allowed_hosts");
    expect(p.risk).toBe("high");
  });

  it("panic: every connector disabled, queued runs dropped, OAuth token revoked at the provider, checklist printed", async () => {
    const okta = fixture("mock-okta-oauth.yaml")
      .replace("client_auth: private_key_jwt", "client_auth: client_secret_post\n    revocation_url: /oauth2/v1/revoke");
    await remote.register(okta, "add");
    await remote.register(ghWith('credential: { revoke_hint: "GitHub > Settings > Developer settings > Tokens: delete it", max_age_days: 90 }'), "add");
    await remote.register(fixture("cisa-kev.yaml").replace("https://www.cisa.gov", "http://localhost:${env.MOCK_PORT}").replace("[www.cisa.gov]", "[localhost]").replace("/sites/default/files/feeds/known_exploited_vulnerabilities.json", "/public/kev.json"), "add");
    for (const [ref, v] of [["mock_client_id", MOCK_TOKENS.clientId], ["mock_client_secret", MOCK_TOKENS.clientSecret], ["mock_bearer", MOCK_TOKENS.bearer]])
      await remote.putSecret("demo", ref!, v!);
    expect((await run("mock-okta-oauth")).status).toBe("success"); // caches an OAuth token in the broker
    expect((await run("mock-github-members")).status).toBe("success");
    await enqueueRun(boss, { connectorId: "cisa-kev", trigger: "schedule" });

    const r = await panic(appPool, { admin: remote, boss, actor: "test", env });
    expect(r.disabled.sort()).toEqual(["cisa-kev", "mock-github-members", "mock-okta-oauth"]);
    expect(r.queued_runs_cancelled).toBe(1);
    expect(r.broker).toEqual({ tokens_revoked: 1, secrets_purged: 0 });
    expect(mock.oauth.revoked).toBe(1);
    const byId = Object.fromEntries(r.checklist.map((c) => [c.connector_id, c]));
    expect(byId["mock-okta-oauth"]!.action).toBe("revoked_by_api");
    expect(byId["mock-github-members"]).toMatchObject({ action: "revoke_manually", detail: "GitHub > Settings > Developer settings > Tokens: delete it" });
    expect(byId["cisa-kev"]!.action).toBe("nothing_to_revoke");

    expect(Number((await appPool.query("select count(*) from connectors where status <> 'disabled'")).rows[0].count)).toBe(0);
    const before = mock.calls.length;
    await expect(remote.request({ connectorId: "mock-github-members", method: "GET", url: `http://localhost:${env.MOCK_PORT}/orgs/acme/members` })).rejects.toThrow(/disabled/);
    expect(mock.calls.length).toBe(before);
    expect((await appPool.query("select kind from alerts where kind = 'panic'")).rowCount).toBe(1);
    expect((await appPool.query("select decision from audit_ledger where action = 'panic'")).rows[0].decision).toBe("allow: 1 revoked, 0 secrets purged");

    // Recovery: re-enable one; the broker has to mint a fresh token (the old one is gone everywhere).
    await setConnectorEnabled(appPool, "mock-okta-oauth", true);
    await remote.forget("mock-okta-oauth");
    expect((await run("mock-okta-oauth")).status).toBe("success");
    expect(mock.oauth.tokenCalls).toBe(2);
  });

  it("panic --purge-secrets deletes every stored secret", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    const r = await panic(appPool, { admin: remote, purgeSecrets: true, env });
    expect(r.broker.secrets_purged).toBe(1);
    expect(await remote.listSecrets()).toEqual([]);
  });

  it("panic without a broker still disables everything and says tokens were NOT wiped", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    const r = await panic(appPool, { env });
    expect(r.disabled).toEqual(["mock-github-members"]);
    expect(r.broker.error).toMatch(/NOT wiped/);
  });

  it("hygiene: idle connector auto-disabled; re-enable restarts the clock; old credential raises a rotate alert", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add"); // idle_disable_days: 14
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    expect((await runHygiene(appPool, { now: Date.now() + 10 * DAY, env })).disabled).toEqual([]);
    const h = await runHygiene(appPool, { now: Date.now() + 15 * DAY, env });
    expect(h.disabled).toEqual(["mock-github-members"]);
    const c = (await appPool.query("select status, disabled_reason from connectors")).rows[0];
    expect(c.status).toBe("disabled");
    expect(c.disabled_reason).toMatch(/^idle for 15 days \(idle_disable_days: 14\)/);
    expect((await appPool.query("select kind from alerts")).rows).toEqual([{ kind: "idle_disabled" }]);

    await setConnectorEnabled(appPool, "mock-github-members", true);
    expect((await runHygiene(appPool, { now: Date.now() + 1 * DAY, env })).disabled).toEqual([]);

    await remote.register(ghWith("credential: { max_age_days: 90 }"), "update");
    const r = await runHygiene(appPool, { now: Date.now() + 100 * DAY, env });
    expect(r.rotate).toEqual(["mock-github-members:mock_bearer"]);
    expect((await runHygiene(appPool, { now: Date.now() + 100 * DAY, env })).rotate).toHaveLength(1);
    expect((await appPool.query("select count(*)::int n from alerts where kind = 'credential_age'")).rows[0].n).toBe(1); // once a day
  });

  it("repeated failures -> one consecutive_failures alert, delivered to Slack by the broker (webhook path never logged)", async () => {
    const hook = `http://localhost:${env.MOCK_PORT}/services/T0001/B0001/${randomBytes(12).toString("hex")}`;
    await remote.register(ghWith(GH_CRED, "alerts: { on_consecutive_failures: 2, slack_webhook_ref: slack_secops }\n"), "add");
    await remote.putSecret("demo", "mock_bearer", "wrong-token-value-0000");
    await remote.putSecret("demo", "slack_secops", hook);
    for (let i = 0; i < 3; i++) expect((await run("mock-github-members")).status).toBe("auth_failed");
    const kinds = (await appPool.query("select kind from alerts order by id")).rows.map((r) => r.kind);
    expect(kinds).toEqual(["auth_failed", "consecutive_failures"]); // auth_failed de-duplicated; streak alert fires once at 2

    const d = await deliverAlerts(appPool, remote);
    expect(d).toEqual({ sent: 2, noChannel: 0, failed: 0 });
    expect(mock.slack.map((m) => m.text)).toEqual([
      ":rotating_light: [IntegrateX] mock-github-members · auth_failed: members: HTTP 401: credentials rejected",
      ":rotating_light: [IntegrateX] mock-github-members · consecutive_failures: 2 consecutive failed runs; last: HTTP 401: credentials rejected",
    ]);
    expect((await appPool.query("select bool_and(delivered) ok from alerts")).rows[0].ok).toBe(true);
    const ledger = JSON.stringify((await appPool.query("select * from audit_ledger where action = 'alert'")).rows);
    expect(ledger).toContain('"path":"[webhook]"');
    expect(ledger).not.toContain(new URL(hook).pathname);
  });

  it("alert webhook pointing at a non-allowed host is refused and retried later", async () => {
    await remote.register(ghWith(GH_CRED, "alerts: { slack_webhook_ref: slack_secops }\n"), "add");
    await remote.putSecret("demo", "slack_secops", "https://exfil.example/services/a/b/c");
    await appPool.query("insert into alerts (connector_id, kind, message) values ('mock-github-members', 'test', 'hello')");
    expect(await deliverAlerts(appPool, remote)).toEqual({ sent: 0, noChannel: 0, failed: 1 });
    expect((await appPool.query("select delivered, channel from alerts")).rows[0]).toEqual({ delivered: false, channel: "error" });
  });

  it("incremental sync: watermark injected next run; only changed records fetched; never moves backwards", async () => {
    const inc = fixture("mock-okta-users.yaml").replace(
      "    pagination: { type: link_header, rel: next }",
      "    pagination: { type: link_header, rel: next }\n    incremental: { cursor_field: lastUpdated, param: search, template: 'lastUpdated gt \"{{cursor}}\"' }",
    );
    await remote.register(inc, "add");
    await remote.putSecret("demo", "mock_ssws", MOCK_TOKENS.ssws);
    const s1 = await run("mock-okta-users");
    expect(s1).toMatchObject({ status: "success", recordsOk: 450, watermark: "2026-01-19T19:00:00.000Z" });
    expect(s1.incrementalFrom).toBeUndefined();

    mock.calls.length = 0;
    const s2 = await run("mock-okta-users");
    expect(s2).toMatchObject({ status: "success", requests: 1, recordsOk: 0, incrementalFrom: "2026-01-19T19:00:00.000Z" });
    expect(s2.watermark).toBeUndefined();
    expect(mock.calls[0]!.query.search).toBe('lastUpdated gt "2026-01-19T19:00:00.000Z"');

    mock.options.touchedUsers = [5, 7];
    const s3 = await run("mock-okta-users");
    expect(s3).toMatchObject({ recordsOk: 2, watermark: "2026-06-01T00:00:00.000Z" });
    expect((await appPool.query("select cursor_value from checkpoints")).rows[0].cursor_value).toBe("2026-06-01T00:00:00.000Z");
    expect((await appPool.query("select count(*)::int n from users")).rows[0].n).toBe(450); // upserts, no duplicates
  });

  it("store_raw keeps a secret-redacted raw copy only when the config opts in", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    await run("mock-github-members");
    expect((await appPool.query("select attributes from users limit 1")).rows[0].attributes._raw).toBeUndefined();
    await remote.register(fixture("mock-github-members.yaml").replace(GH_CRED, `${GH_CRED}\ndata: { store_raw: true, redact_secrets: true }`), "update");
    await run("mock-github-members");
    const raw = (await appPool.query("select attributes from users where source_id = '1001'")).rows[0].attributes._raw;
    expect(raw).toMatchObject({ login: "dev1", id: 1001 });
  });

  it("API: posture, disable/enable and panic routes (panic needs the admin token)", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    const admin = "admin-token-phase7-xyz";
    const app = buildApi({ pool: appPool, env, adminToken: admin, broker: remote, admin: remote, boss });
    expect((await app.inject({ url: "/v1/connectors/mock-github-members/posture" })).json()).toMatchObject({ connector_id: "mock-github-members", auth_type: "bearer" });
    expect((await app.inject({ method: "POST", url: "/v1/panic" })).statusCode).toBe(401);
    const h = { authorization: `Bearer ${admin}` };
    expect((await app.inject({ method: "POST", url: "/v1/connectors/mock-github-members/disable", headers: h })).json()).toEqual({ id: "mock-github-members", status: "disabled" });
    expect((await app.inject({ method: "POST", url: "/v1/connectors/mock-github-members/enable", headers: h })).json()).toEqual({ id: "mock-github-members", status: "enabled" });
    const p = await app.inject({ method: "POST", url: "/v1/panic", headers: { ...h, "content-type": "application/json" }, payload: "{}" });
    expect(p.json()).toMatchObject({ disabled: ["mock-github-members"], broker: { tokens_revoked: 0 } });
    expect((await app.inject({ url: "/v1/alerts" })).json().alerts[0].kind).toBe("panic");
  });
});
