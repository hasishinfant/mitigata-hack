// Phase 6: broker as a separate process on a Unix socket. Workers/API/CLI hold no secrets;
// configs must be broker-signed; secrets are write-only; every call and denial lands in a hash-chained ledger.
import { randomBytes } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApi } from "../src/api/server.ts";
import { configSigKey, signConfig, verifyConfigSig } from "../src/broker/configSig.ts";
import { createRemoteBroker, type RemoteBroker } from "../src/broker/remote.ts";
import { createBrokerServer, listenOnSocket } from "../src/broker/server.ts";
import { BrokerError } from "../src/broker/types.ts";
import { assertNoBrokerSecrets, withoutBrokerSecrets } from "../src/envfiles.ts";
import { runConnector } from "../src/engine/runner.ts";
import { scanForSecrets } from "../src/security/leakcheck.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector } from "../src/store/connectors.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { createWorker } from "../src/worker/worker.ts";
import { buildMock, MOCK_TOKENS, type Mock } from "../mock/server.ts";
import { clearData, hasDb, regPool, testUrl } from "./helpers/db.ts";

const fixture = (name: string) => readFileSync(join(import.meta.dirname, "fixtures/configs", name), "utf8");

describe("env separation", () => {
  it("app processes refuse to start with broker secrets in their environment", () => {
    expect(() => assertNoBrokerSecrets("worker", { DATABASE_URL_APP: "x" })).not.toThrow();
    expect(() => assertNoBrokerSecrets("worker", { IX_MASTER_KEY: "k" })).toThrow(/worker refuses to start.*IX_MASTER_KEY/);
    expect(() => assertNoBrokerSecrets("api", { DATABASE_URL_BROKER: "u", IX_SECRET_GITHUB_PAT: "t" })).toThrow(/DATABASE_URL_BROKER, IX_SECRET_GITHUB_PAT/);
  });
  it("workers and the scheduler refuse the broker admin token; the API may hold it", () => {
    expect(() => assertNoBrokerSecrets("worker", { IX_BROKER_ADMIN_TOKEN: "t" })).toThrow(/worker refuses to start.*IX_BROKER_ADMIN_TOKEN/);
    expect(() => assertNoBrokerSecrets("scheduler", { IX_BROKER_ADMIN_TOKEN: "t" })).toThrow(/IX_BROKER_ADMIN_TOKEN/);
    expect(() => assertNoBrokerSecrets("api", { IX_BROKER_ADMIN_TOKEN: "t" }, { adminTokenAllowed: true })).not.toThrow();
    expect(withoutBrokerSecrets({ PATH: "/bin", IX_BROKER_ADMIN_TOKEN: "t" })).toEqual({ PATH: "/bin" });
  });
  it("spawned app processes get an environment without them", () => {
    const env = withoutBrokerSecrets({ PATH: "/bin", IX_MASTER_KEY: "k", DATABASE_URL_ADMIN: "a", IX_SECRET_X: "s", DATABASE_URL_APP: "app" });
    expect(env).toEqual({ PATH: "/bin", DATABASE_URL_APP: "app" });
  });
});

describe("config signatures", () => {
  const key = configSigKey(Buffer.alloc(32, 1));
  it("verify only for the exact id, version and hash", () => {
    const sig = signConfig(key, "gh", 3, "abc");
    expect(verifyConfigSig(key, "gh", 3, "abc", sig)).toBe(true);
    expect(verifyConfigSig(key, "gh", 4, "abc", sig)).toBe(false);
    expect(verifyConfigSig(key, "gh", 3, "abd", sig)).toBe(false);
    expect(verifyConfigSig(key, "other", 3, "abc", sig)).toBe(false);
    expect(verifyConfigSig(configSigKey(Buffer.alloc(32, 2)), "gh", 3, "abc", sig)).toBe(false);
    expect(verifyConfigSig(key, "gh", 3, "abc", null)).toBe(false);
    expect(verifyConfigSig(key, "gh", 3, "abc", "zz")).toBe(false);
  });
});

describe("leak scanner", () => {
  const secret = { ref: "demo/github_pat", value: "ghp_" + "Z".repeat(36) };
  it("finds raw, base64 and URL-encoded copies, and names only the ref", () => {
    const hits = scanForSecrets([secret, { ref: "demo/x", value: "p@ss word/123" }], [
      { name: "log", text: `token=${secret.value}` },
      { name: "dump", text: Buffer.from(secret.value).toString("base64") },
      { name: "url", text: "q=p%40ss%20word%2F123" },
      { name: "clean", text: "nothing here" },
    ]);
    expect(hits).toEqual([
      { ref: "demo/github_pat", target: "log", form: "raw" },
      { ref: "demo/github_pat", target: "dump", form: "base64" },
      { ref: "demo/x", target: "url", form: "urlencoded" },
    ]);
  });
});

describe.skipIf(!hasDb)("broker process over a Unix socket", () => {
  let mock: Mock;
  let appPool: Pool;
  let brokerPool: Pool;
  let adminPool: Pool;
  let server: ReturnType<typeof createBrokerServer>;
  let remote: RemoteBroker;
  let env: Record<string, string | undefined>;
  const socketPath = join(tmpdir(), `ixb-${process.pid}.sock`);
  const adminSocketPath = join(tmpdir(), `ixba-${process.pid}.sock`);
  const adminToken = randomBytes(16).toString("hex");
  const masterKey = randomBytes(32);
  let ledgerStart = 0; // the ledger is append-only and shared by all test files: only look at this test's rows

  beforeAll(async () => {
    mock = buildMock();
    await mock.app.listen({ host: "127.0.0.1", port: 0 });
    env = { ...process.env, MOCK_PORT: String((mock.app.server.address() as AddressInfo).port) };
    appPool = createPool(testUrl("DATABASE_URL_APP"));
    brokerPool = createPool(testUrl("DATABASE_URL_BROKER"));
    adminPool = createPool(testUrl("DATABASE_URL_ADMIN"));
    server = createBrokerServer({ pool: brokerPool, masterKey, env, adminToken });
    await listenOnSocket(server.app, socketPath);
    await listenOnSocket(server.adminApp, adminSocketPath);
    remote = createRemoteBroker(socketPath, { adminSocketPath, adminToken });
  });
  afterAll(async () => {
    await server?.app.close();
    await server?.adminApp.close();
    await Promise.all([appPool?.end(), brokerPool?.end(), adminPool?.end()]);
    await mock?.app.close();
  });
  beforeEach(async () => {
    await clearData(appPool);
    await remote.forget();
    mock.calls.length = 0;
    ledgerStart = Number((await appPool.query("select coalesce(max(seq), 0) as s from audit_ledger")).rows[0].s);
  });

  const ledger = async () =>
    (await appPool.query("select action, connector_id, method, host, path, status, decision from audit_ledger where seq > $1 order by seq", [ledgerStart])).rows;
  const port = () => env.MOCK_PORT;

  it("sockets are private to this OS user (0600)", () => {
    expect(statSync(socketPath).mode & 0o777).toBe(0o600);
    expect(statSync(adminSocketPath).mode & 0o777).toBe(0o600);
  });

  it("the request socket serves no admin routes; the admin socket needs the token", async () => {
    const yaml = fixture("mock-github-members.yaml");
    // A worker that somehow learned a token still can't reach admin routes on the socket it is given.
    const onRequestSocket = createRemoteBroker(socketPath, { adminSocketPath: socketPath, adminToken });
    await expect(onRequestSocket.register(yaml, "add")).rejects.toMatchObject({ statusCode: 404 });
    await expect(onRequestSocket.putSecret("demo", "mock_bearer", "x")).rejects.toMatchObject({ statusCode: 404 });
    await expect(onRequestSocket.panic({ purgeSecrets: true })).rejects.toMatchObject({ statusCode: 404 });
    // Wrong or missing token on the admin socket: refused and written to the ledger.
    const wrong = createRemoteBroker(socketPath, { adminSocketPath, adminToken: "not-the-token" });
    await expect(wrong.register(yaml, "add")).rejects.toMatchObject({ statusCode: 401 });
    await expect(createRemoteBroker(socketPath, { adminSocketPath, adminToken: "" }).register(yaml, "add")).rejects.toThrow(/IX_BROKER_ADMIN_TOKEN is not set/);
    expect((await appPool.query("select count(*)::int as n from connectors")).rows[0].n).toBe(0);
    expect(await ledger()).toContainEqual(expect.objectContaining({ action: "admin", path: "/v1/connectors", decision: "deny: bad or missing broker admin token" }));
    // Request-socket routes still work for workers.
    expect(await onRequestSocket.ping()).toBe(true);
  });

  it("a config that would send an existing secret to a new host needs --confirm-hosts", async () => {
    const yaml = fixture("mock-github-members.yaml");
    await remote.register(yaml, "add", "test");
    const moved = yaml.replace("allowed_hosts: [localhost]", "allowed_hosts: [localhost, evil.example.net]");
    await expect(remote.register(moved, "update", "test")).rejects.toMatchObject({ statusCode: 409, message: expect.stringMatching(/mock_bearer.*evil\.example\.net.*--confirm-hosts/) });
    // A brand-new connector reusing the ref against another host is refused the same way.
    const copy = moved.replace("id: mock-github-members", "id: copy-of-members");
    await expect(remote.register(copy, "add", "test")).rejects.toMatchObject({ statusCode: 409 });
    expect((await appPool.query("select count(*)::int as n from connector_versions")).rows[0].n).toBe(1);
    // Confirmed by the operator: allowed, and the ledger says so.
    const r = await remote.register(moved, "update", "test", { confirmHosts: true });
    expect(r).toMatchObject({ version: 2, changed: true, newHosts: ["evil.example.net"] });
    expect((await ledger()).map((e) => e.decision)).toContain("allow: v2; secrets now also sent to evil.example.net (confirmed)");
  });

  it("register -> broker signs; secret is write-only; sync runs through the socket", async () => {
    const r = await remote.register(fixture("mock-github-members.yaml"), "add", "test");
    expect(r).toEqual({ id: "mock-github-members", version: 1, changed: true });
    expect((await appPool.query("select broker_sig from connector_versions")).rows[0].broker_sig).toMatch(/^[0-9a-f]{64}$/);

    const put = await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    expect(put).toMatchObject({ ok: true, chars: MOCK_TOKENS.bearer.length });
    const list = await remote.listSecrets("demo");
    expect(list.map((s) => s.ref)).toEqual(["mock_bearer"]);
    expect(JSON.stringify(list)).not.toContain(MOCK_TOKENS.bearer);

    const conn = await loadActiveConnector(appPool, "mock-github-members", env);
    const [s] = await runConnector({ connector: conn, broker: remote, store: createPgRunStore(appPool) });
    expect(s).toMatchObject({ status: "success", requests: 3, recordsOk: 250 });

    const l = await ledger();
    expect(l.filter((e) => e.action === "request" && e.decision === "allow")).toHaveLength(3);
    expect(l.map((e) => e.action)).toEqual(expect.arrayContaining(["register", "secret_set"]));
    expect(JSON.stringify(l)).not.toContain(MOCK_TOKENS.bearer);
    expect(l.every((e) => !String(e.path ?? "").includes("?"))).toBe(true); // paths only, never query strings
  });

  it("the app DB role cannot read credentials or write config versions", async () => {
    await expect(appPool.query("select * from credentials")).rejects.toThrow(/permission denied/);
    await expect(
      appPool.query("insert into connector_versions (connector_id, version, config_yaml, config_hash) values ('x', 1, 'y', 'z')"),
    ).rejects.toThrow(/permission denied/);
    await expect(appPool.query("delete from tenants")).rejects.toThrow(/permission denied/);
  });

  it("denials keep their kind over the socket and are written to the ledger", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    const deny = (url: string, method: "GET" | "POST" = "GET") =>
      expect(remote.request({ connectorId: "mock-github-members", method, url, body: method === "POST" ? {} : undefined })).rejects.toSatisfy(
        (e) => e instanceof BrokerError && e.kind === "policy_denied",
      );
    await deny(`https://evil.test/orgs/acme/members`);
    await deny(`http://localhost:${port()}/rest/json/cves/2.0`);
    await deny(`http://localhost:${port()}/orgs/acme/members`, "POST");
    expect(mock.calls).toHaveLength(0);
    const denials = (await ledger()).filter((e) => String(e.decision).startsWith("deny"));
    expect(denials.map((d) => d.decision)).toEqual([
      "deny: host evil.test not in allowed_hosts",
      "deny: path /rest/json/cves/2.0 not in allowed_paths",
      "deny: POST to /orgs/acme/members not in read_only_post",
    ]);
  });

  it("a config row the broker did not sign is refused, even if it is the active version", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    // Simulate a compromised database: a rogue version that sends the bearer token to another host.
    const evil = fixture("mock-github-members.yaml").replace("allowed_hosts: [localhost]", "allowed_hosts: [localhost, evil.test]");
    await adminPool.query(
      "insert into connector_versions (connector_id, version, config_yaml, config_hash, broker_sig) values ('mock-github-members', 2, $1, 'forged', $2)",
      [evil, "0".repeat(64)],
    );
    await adminPool.query("update connectors set active_version = 2 where id = 'mock-github-members'");
    await remote.forget("mock-github-members");
    await expect(
      remote.request({ connectorId: "mock-github-members", method: "GET", url: `http://localhost:${port()}/orgs/acme/members` }),
    ).rejects.toThrow(/not approved by the broker/);
    expect(mock.calls).toHaveLength(0);
    expect((await ledger()).at(-1)!.decision).toMatch(/^deny: connector mock-github-members v2 was not approved by the broker/);
  });

  it("the app DB role can disable and pause, but not re-enable or switch the active config version", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.register(fixture("mock-github-members.yaml").replace("max_requests_per_run: 50", "max_requests_per_run: 40"), "update");
    await expect(appPool.query("update connectors set active_version = 1")).rejects.toThrow(/permission denied/);
    await appPool.query("update connectors set status = 'paused', paused_until = now() + interval '1 minute'"); // breaker: allowed
    await appPool.query("update connectors set status = 'enabled', paused_until = null"); // half-open: allowed
    await appPool.query("update connectors set status = 'disabled'"); // kill switch: allowed
    await expect(appPool.query("update connectors set status = 'enabled'")).rejects.toThrow(/only the broker can re-enable/);
    // The breaker can't turn a disabled connector into a paused one either.
    await createPgRunStore(appPool).pause("mock-github-members", new Date(Date.now() + 60_000), "test");
    expect((await appPool.query("select status, active_version from connectors")).rows[0]).toEqual({ status: "disabled", active_version: 2 });
    await expect(createRemoteBroker(socketPath, { adminSocketPath, adminToken: "nope" }).enableConnector("mock-github-members")).rejects.toMatchObject({ statusCode: 401 });
    expect(await remote.enableConnector("mock-github-members")).toEqual({ id: "mock-github-members", status: "enabled" });
    await expect(remote.enableConnector("no-such")).rejects.toMatchObject({ statusCode: 404 });
  });

  it("disabling a connector stops the broker from calling out for it", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    await appPool.query("update connectors set status = 'disabled'");
    await remote.forget("mock-github-members");
    await expect(
      remote.request({ connectorId: "mock-github-members", method: "GET", url: `http://localhost:${port()}/orgs/acme/members` }),
    ).rejects.toThrow(/connector is disabled/);
    expect(mock.calls).toHaveLength(0);
  });

  it("inline test: allowed for a no-auth config, refused for one that uses secrets", async () => {
    const kev = fixture("cisa-kev.yaml")
      .replace("base_url: https://www.cisa.gov", "base_url: http://localhost:${env.MOCK_PORT}")
      .replace("allowed_hosts: [www.cisa.gov]", "allowed_hosts: [localhost]")
      .replace("/sites/default/files/feeds/known_exploited_vulnerabilities.json", "/public/kev.json");
    const t = await remote.testInline(kev);
    expect(t.ok).toBe(true);
    expect(t.streams[0]).toMatchObject({ recordsOnPage: 25, hasMorePages: false });
    expect(t.streams[0]!.samples).toHaveLength(3);

    await expect(remote.testInline(fixture("mock-github-members.yaml"))).rejects.toThrow(/must be registered first/);
  });

  it("worker runs jobs through the broker socket with no secret source of its own", async () => {
    await remote.register(fixture("mock-okta-users.yaml"), "add");
    await remote.putSecret("demo", "mock_ssws", MOCK_TOKENS.ssws);
    const worker = createWorker({ pool: appPool, broker: remote, env });
    const [s] = await worker.handle({ connectorId: "mock-okta-users", trigger: "schedule" });
    expect(s).toMatchObject({ status: "success", recordsOk: 450 });
  });

  it("API: secrets and registration go to the broker; responses never carry a value", async () => {
    const admin = "admin-token-for-test-123456";
    const app = buildApi({ pool: appPool, env, adminToken: admin, broker: remote, admin: remote });
    const h = { authorization: `Bearer ${admin}` };
    const put = await app.inject({ method: "PUT", url: "/v1/secrets/mock_api_key", headers: h, payload: { value: MOCK_TOKENS.apiKey } });
    expect(put.json()).toEqual({ stored: true, tenant: "demo", ref: "mock_api_key", chars: MOCK_TOKENS.apiKey.length });
    expect(put.body).not.toContain(MOCK_TOKENS.apiKey);
    const reg = await app.inject({ method: "POST", url: "/v1/connectors", headers: { ...h, "content-type": "text/yaml" }, payload: fixture("mock-nvd-cves.yaml") });
    expect(reg.statusCode).toBe(201);
    const bad = await app.inject({ method: "POST", url: "/v1/connectors", headers: { ...h, "content-type": "text/yaml" }, payload: fixture("bad-host.yaml") });
    expect(bad.statusCode).toBe(422);
    const test = await app.inject({ method: "POST", url: "/v1/connectors/mock-nvd-cves/test", headers: h });
    expect(test.json()).toMatchObject({ ok: true, connectorId: "mock-nvd-cves" });
  });

  it("remove: connector, its config versions, runs and records are gone; secret is kept", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    const conn = await loadActiveConnector(appPool, "mock-github-members", env);
    await runConnector({ connector: conn, broker: remote, store: createPgRunStore(appPool) });
    expect(await remote.removeConnector("mock-github-members")).toEqual({ removed: true, records: 250 });
    for (const t of ["connectors", "connector_versions", "runs", "users"])
      expect(Number((await appPool.query(`select count(*) from ${t}`)).rows[0].count)).toBe(0);
    expect((await remote.listSecrets()).map((x) => x.ref)).toEqual(["mock_bearer"]); // kept without purge
    expect((await ledger()).at(-1)).toMatchObject({ action: "remove", decision: "allow: 250 records deleted" });
    await expect(remote.removeConnector("mock-github-members")).rejects.toThrow(/not found/);
  });

  it("remove with purge: deletes the connector's own secrets but keeps one another connector still uses", async () => {
    // Two connectors share mock_bearer; okta has its own mock_ssws.
    const second = fixture("mock-github-members.yaml").replace("id: mock-github-members", "id: mock-github-copy");
    await remote.register(fixture("mock-github-members.yaml"), "add");
    await remote.register(second, "add");
    await remote.register(fixture("mock-okta-users.yaml"), "add");
    await remote.putSecret("demo", "mock_bearer", MOCK_TOKENS.bearer);
    await remote.putSecret("demo", "mock_ssws", MOCK_TOKENS.ssws);
    expect(await remote.removeConnector("mock-okta-users", { purgeSecrets: true })).toMatchObject({ secrets: { deleted: ["mock_ssws"], kept_shared: [] } });
    expect(await remote.removeConnector("mock-github-members", { purgeSecrets: true })).toMatchObject({ secrets: { deleted: [], kept_shared: ["mock_bearer"] } });
    expect((await remote.listSecrets()).map((x) => x.ref)).toEqual(["mock_bearer"]);
    expect(await remote.removeConnector("mock-github-copy", { purgeSecrets: true })).toMatchObject({ secrets: { deleted: ["mock_bearer"], kept_shared: [] } });
    expect(await remote.listSecrets()).toEqual([]);
  });

  it("dashboard builder routes: inline test (no-auth only) and remove; page has the new buttons", async () => {
    const admin = "admin-token-for-builder-1";
    const app = buildApi({ pool: appPool, env, adminToken: admin, broker: remote, admin: remote });
    const h = { authorization: `Bearer ${admin}`, "content-type": "text/yaml" };
    const kev = fixture("cisa-kev.yaml")
      .replace("base_url: https://www.cisa.gov", "base_url: http://localhost:${env.MOCK_PORT}")
      .replace("allowed_hosts: [www.cisa.gov]", "allowed_hosts: [localhost]")
      .replace("/sites/default/files/feeds/known_exploited_vulnerabilities.json", "/public/kev.json");
    expect((await app.inject({ method: "POST", url: "/v1/configs/test", headers: { "content-type": "text/yaml" }, payload: kev })).statusCode).toBe(401);
    const t = await app.inject({ method: "POST", url: "/v1/configs/test", headers: h, payload: kev });
    expect(t.json()).toMatchObject({ ok: true, streams: [{ recordsOnPage: 25 }] });
    expect((await app.inject({ method: "POST", url: "/v1/configs/test", headers: h, payload: fixture("mock-github-members.yaml") })).statusCode).toBe(409);

    await remote.register(fixture("mock-github-members.yaml"), "add");
    const del = await app.inject({ method: "DELETE", url: "/v1/connectors/mock-github-members", headers: { authorization: `Bearer ${admin}` } });
    expect(del.json()).toEqual({ id: "mock-github-members", removed: true, records: 0, secrets: { deleted: [], kept_shared: [] } });
    expect((await app.inject({ method: "DELETE", url: "/v1/connectors/mock-github-members", headers: { authorization: `Bearer ${admin}` } })).statusCode).toBe(404);

    const page = (await app.inject({ url: "/" })).body;
    expect(page).toContain("＋ Add connector");
    expect(page).toContain('id="open-remove"');
    expect(page).not.toContain("remove-confirm");
    const js = await app.inject({ url: "/builder.js" });
    expect(js.statusCode).toBe(200);
    expect(js.body).not.toContain("innerHTML");
  });

  it("ledger: chain verifies, and an edited row is detected (run last: it tampers)", async () => {
    await remote.register(fixture("mock-github-members.yaml"), "add");
    expect(await remote.verifyLedger()).toMatchObject({ ok: true });
    // Even the table owner can't UPDATE (trigger); an attacker with superuser could disable it. Do that:
    await adminPool.query("alter table audit_ledger disable trigger audit_ledger_no_update");
    const { seq, decision } = (await adminPool.query("select seq, decision from audit_ledger order by seq desc limit 1")).rows[0];
    await adminPool.query("update audit_ledger set decision = 'allow: nothing to see' where seq = $1", [seq]);
    const check = await remote.verifyLedger();
    expect(check).toMatchObject({ ok: false, firstBadSeq: Number(seq) });
    expect(check.problem).toContain("was modified after it was written");
    await adminPool.query("update audit_ledger set decision = $2 where seq = $1", [seq, decision]); // restore
    await adminPool.query("alter table audit_ledger enable trigger audit_ledger_no_update");
    expect(await remote.verifyLedger()).toMatchObject({ ok: true });
  });
});
