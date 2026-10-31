// Phase 4: OAuth2 (private_key_jwt, client_secret_basic/post), token caching and refresh,
// encrypted secret store, read-only POST policy, and coverage connectors for vendor APIs on mocks.
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createLocalBroker, type LocalBroker } from "../src/broker/client.ts";
import { dbSecretSource, envSecretSource, putSecret, seal, unseal } from "../src/broker/secrets.ts";
import { BrokerError } from "../src/broker/types.ts";
import type { ResolvedConnector } from "../src/config/load.ts";
import { validateConfigText } from "../src/config/validate.ts";
import { runConnector } from "../src/engine/runner.ts";
import { testConnection } from "../src/engine/testConnection.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector, registerConnector } from "../src/store/connectors.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { buildMock, MOCK_TOKENS, type Mock } from "../mock/server.ts";
import { fakeClock } from "./helpers/clock.ts";
import { clearData, hasDb, testUrl } from "./helpers/db.ts";

const root = join(import.meta.dirname, "..");
const read = (rel: string) => readFileSync(join(root, rel), "utf8");
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PRIVATE_PEM = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const PUBLIC_PEM = publicKey.export({ type: "spki", format: "pem" }).toString();

const secrets = {
  IX_SECRET_MOCK_CLIENT_ID: MOCK_TOKENS.clientId,
  IX_SECRET_MOCK_CLIENT_SECRET: MOCK_TOKENS.clientSecret,
  IX_SECRET_MOCK_PRIVATE_KEY: PRIVATE_PEM,
  IX_SECRET_CROWDSTRIKE_CLIENT_ID: MOCK_TOKENS.clientId,
  IX_SECRET_CROWDSTRIKE_CLIENT_SECRET: MOCK_TOKENS.clientSecret,
  IX_SECRET_VISIONONE_TOKEN: MOCK_TOKENS.visionOne,
  IX_SECRET_NETSKOPE_TOKEN: MOCK_TOKENS.netskope,
  IX_SECRET_FORTIGATE_TOKEN: MOCK_TOKENS.fortigate,
  IX_SECRET_ELASTIC_API_KEY: MOCK_TOKENS.elastic,
};

describe("secret store crypto", () => {
  const mk = Buffer.alloc(32, 7);
  it("round-trips and never stores plaintext", () => {
    const s = seal(mk, "demo", "github_pat", "super-secret-value-123");
    expect(s.ciphertext.toString("utf8")).not.toContain("super-secret");
    expect(unseal(mk, "demo", "github_pat", s)).toBe("super-secret-value-123");
  });
  it("fails with the wrong master key or when the row is moved to another ref", () => {
    const s = seal(mk, "demo", "github_pat", "v");
    expect(() => unseal(Buffer.alloc(32, 8), "demo", "github_pat", s)).toThrow();
    expect(() => unseal(mk, "demo", "nvd_key", s)).toThrow();
    expect(() => unseal(mk, "other", "github_pat", s)).toThrow();
  });
  it("uses a fresh data key and nonce per secret", () => {
    const a = seal(mk, "demo", "x", "same");
    const b = seal(mk, "demo", "x", "same");
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
    expect(a.wrappedDek.equals(b.wrappedDek)).toBe(false);
  });
});

describe("validator: read-only POST", () => {
  const base = read("connectors/coverage/elastic-security-alerts.yaml");
  it("POST needs the path in policy.read_only_post", () => {
    const res = validateConfigText(base.replace("  read_only_post: [/.alerts-security.alerts-default/_search]\n", ""));
    expect(res.errors[0]!.message).toContain("needs the path in policy.read_only_post");
  });
  it("GET with a body is refused", () => {
    const res = validateConfigText(base.replace("method: POST", "method: GET"));
    expect(res.errors.map((e) => e.message).join("\n")).toContain("request.body is only allowed with method POST");
  });
  it("DELETE is still refused", () => {
    expect(validateConfigText(base.replace("method: POST", "method: DELETE")).ok).toBe(false);
  });
});

describe.skipIf(!hasDb)("Phase 4 on mocks", () => {
  let mock: Mock;
  let pool: Pool;
  let brokerPool: Pool;
  let env: Record<string, string | undefined>;

  beforeAll(async () => {
    mock = buildMock({ jwtPublicKey: PUBLIC_PEM });
    await mock.app.listen({ host: "127.0.0.1", port: 0 });
    const port = (mock.app.server.address() as AddressInfo).port;
    const api = `http://localhost:${port}`;
    env = {
      ...process.env,
      MOCK_PORT: String(port),
      CROWDSTRIKE_API: api, CROWDSTRIKE_HOST: "localhost",
      VISIONONE_API: api, VISIONONE_HOST: "localhost",
      NETSKOPE_API: api, NETSKOPE_HOST: "localhost",
      FORTIGATE_API: api, FORTIGATE_HOST: "localhost",
      ELASTIC_API: api, ELASTIC_HOST: "localhost",
    };
    pool = createPool(testUrl("DATABASE_URL_APP"));
    brokerPool = createPool(testUrl("DATABASE_URL_BROKER"));
  });
  afterAll(async () => {
    await brokerPool?.query("delete from credentials");
    await pool?.end();
    await brokerPool?.end();
    await mock?.app.close();
  });
  beforeEach(async () => {
    await brokerPool.query("delete from credentials");
    await clearData(pool);
    mock.calls.length = 0;
    mock.oauth.tokenCalls = 0;
    mock.oauth.revokeAll();
    mock.options.grantedScope = "";
    mock.options.tokenTtlS = 1799;
  });

  async function setup(text: string, opts: { secrets?: Record<string, string>; clock?: ReturnType<typeof fakeClock>["clock"] } = {}) {
    const { id } = await registerConnector(pool, text, { env });
    const conn = await loadActiveConnector(pool, id, env);
    const broker = createLocalBroker({
      getConnector: (cid) => (cid === conn.metadata.id ? conn : undefined),
      secrets: envSecretSource(opts.secrets ?? secrets),
      ...(opts.clock ? { clock: opts.clock } : {}),
    });
    return { conn, broker };
  }
  const runWith = async (conn: ResolvedConnector, broker: LocalBroker) =>
    (await runConnector({ connector: conn, broker, store: createPgRunStore(pool) }))[0]!;
  const oauthFixture = (clientAuth = "private_key_jwt") =>
    read("test/fixtures/configs/mock-okta-oauth.yaml").replace("client_auth: private_key_jwt", `client_auth: ${clientAuth}`);

  // ---------- OAuth2 ----------
  it("private_key_jwt: signed assertion has iss, sub, aud, exp, jti and kid; one token for all pages", async () => {
    const { conn, broker } = await setup(oauthFixture());
    const s = await runWith(conn, broker);
    expect(s).toMatchObject({ status: "success", requests: 3, recordsOk: 450 });
    expect(mock.oauth.tokenCalls).toBe(1);
    const a = mock.oauth.lastAssertion!;
    expect(a.header).toMatchObject({ alg: "RS256", kid: "mock-kid-1" });
    expect(a.payload.iss).toBe(MOCK_TOKENS.clientId);
    expect(a.payload.sub).toBe(MOCK_TOKENS.clientId);
    expect(a.payload.aud).toBe(`http://localhost:${env.MOCK_PORT}/oauth2/v1/token`);
    expect(Number(a.payload.exp) - Number(a.payload.iat)).toBe(300);
    expect(a.payload.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(broker.credentialInfo(conn.metadata.id)).toMatchObject({ grantedScopes: ["okta.users.read"], scopeSource: "token_response" });
  });

  it("client_secret_basic and client_secret_post both work", async () => {
    for (const mode of ["client_secret_basic", "client_secret_post"]) {
      await clearData(pool);
      const { conn, broker } = await setup(oauthFixture(mode));
      expect((await runWith(conn, broker)).status).toBe("success");
    }
    expect(mock.oauth.tokenCalls).toBe(2);
  });

  it("revoked token: 401 -> refresh once -> success", async () => {
    const { conn, broker } = await setup(oauthFixture("client_secret_post"));
    await runWith(conn, broker);
    mock.oauth.revokeAll();
    const s = await runWith(conn, broker);
    expect(s.status).toBe("success");
    expect(mock.oauth.tokenCalls).toBe(2);
  });

  it("token refreshed 60 s before expiry", async () => {
    mock.options.tokenTtlS = 120;
    const fc = fakeClock();
    const { conn, broker } = await setup(oauthFixture("client_secret_post"), { clock: fc.clock });
    await runWith(conn, broker);
    await fc.clock.sleep(30_000, "backoff"); // 90 s left: still valid
    await runWith(conn, broker);
    expect(mock.oauth.tokenCalls).toBe(1);
    await fc.clock.sleep(31_000, "backoff"); // 59 s left: inside the refresh window
    await runWith(conn, broker);
    expect(mock.oauth.tokenCalls).toBe(2);
  });

  it("wrong client secret: auth_failed with the provider's error code, no secret in the message", async () => {
    const { conn, broker } = await setup(oauthFixture("client_secret_post"), { secrets: { ...secrets, IX_SECRET_MOCK_CLIENT_SECRET: "wrong-secret-0000" } });
    const s = await runWith(conn, broker);
    expect(s.status).toBe("auth_failed");
    expect(s.lastError).toBe("auth_failed: token request failed (invalid_client: Client authentication failed)");
    expect(s.lastError).not.toContain("wrong-secret");
  });

  it("over-privileged token is visible: granted scopes reported beyond expected", async () => {
    mock.options.grantedScope = "okta.users.read okta.users.manage";
    const { conn, broker } = await setup(oauthFixture("client_secret_post"));
    const t = await testConnection(conn, broker);
    expect(t.ok).toBe(true);
    expect(t.credential.grantedScopes).toEqual(["okta.users.read", "okta.users.manage"]);
    expect(t.streams[0]!.samples).toHaveLength(3);
    expect((await pool.query("select count(*) from users")).rows[0].count).toBe("0"); // test writes nothing
  });

  it("the token endpoint is the only POST target for a GET connector", async () => {
    const { conn, broker } = await setup(oauthFixture("client_secret_post"));
    const before = mock.calls.length;
    await expect(
      broker.request({ connectorId: conn.metadata.id, method: "POST", url: `http://localhost:${env.MOCK_PORT}/api/v1/users`, body: {} }),
    ).rejects.toSatisfy((e) => e instanceof BrokerError && e.kind === "policy_denied");
    await expect(
      broker.request({ connectorId: conn.metadata.id, method: "GET", url: `http://localhost:${env.MOCK_PORT}/oauth2/v1/token` }),
    ).rejects.toSatisfy((e) => e instanceof BrokerError && e.kind === "policy_denied");
    expect(mock.calls.length).toBe(before);
  });

  // ---------- encrypted secret store ----------
  it("secrets from the encrypted store; app role cannot read credentials", async () => {
    const mk = Buffer.alloc(32, 3);
    await putSecret(brokerPool, mk, "demo", "visionone_token", MOCK_TOKENS.visionOne);
    await expect(pool.query("select * from credentials")).rejects.toThrow(/permission denied/);
    const raw = (await brokerPool.query("select ciphertext, wrapped_dek from credentials")).rows[0];
    expect(Buffer.concat([raw.ciphertext, raw.wrapped_dek]).toString("latin1")).not.toContain(MOCK_TOKENS.visionOne);

    const { id } = await registerConnector(pool, read("connectors/coverage/trendmicro-visionone-alerts.yaml"), { env });
    const conn = await loadActiveConnector(pool, id, env);
    const broker = createLocalBroker({ getConnector: () => conn, secrets: dbSecretSource(brokerPool, mk) });
    expect((await runWith(conn, broker)).status).toBe("success");
    const meta = (await brokerPool.query("select last_used_at from credentials")).rows[0];
    expect(meta.last_used_at).toBeTruthy();
  });

  // ---------- coverage connectors ----------
  it("CrowdStrike-like devices: OAuth2 + offset -> devices table with IPs", async () => {
    const { conn, broker } = await setup(read("connectors/coverage/crowdstrike-devices.yaml"));
    expect(await runWith(conn, broker)).toMatchObject({ status: "success", requests: 3, recordsOk: 230 });
    const d = (await pool.query("select hostname, host(ip) as ip, os, owner, last_seen from devices where source_id = 'cs00000004'")).rows[0];
    expect(d).toEqual({ hostname: "WS-1004", ip: "10.20.0.5", os: "Mac macOS 15", owner: "user4", last_seen: "2026-01-01T04:00:00.000Z" });
  });

  it("Trend Vision One-like alerts: nextLink in body", async () => {
    const { conn, broker } = await setup(read("connectors/coverage/trendmicro-visionone-alerts.yaml"));
    expect(await runWith(conn, broker)).toMatchObject({ status: "success", requests: 3, recordsOk: 120 });
  });

  it("Netskope-like alerts: custom header, offset without total, epoch seconds", async () => {
    const { conn, broker } = await setup(read("connectors/coverage/netskope-alerts.yaml"));
    expect(await runWith(conn, broker)).toMatchObject({ status: "success", requests: 3, recordsOk: 260 });
    const e = (await pool.query("select ts, type, description from events where source_id = 'ns0000001'")).rows[0];
    expect(e).toEqual({ ts: "2026-01-01T00:01:00.000Z", type: "malware", description: "Malware Download - user1@example.test" });
  });

  it("FortiGate-like devices: single page, MAC as id", async () => {
    const { conn, broker } = await setup(read("connectors/coverage/fortigate-devices.yaml"));
    expect(await runWith(conn, broker)).toMatchObject({ status: "success", requests: 1, recordsOk: 40 });
  });

  it("Elastic-like alerts: read-only POST with paging in the body, dotted field names", async () => {
    const { conn, broker } = await setup(read("connectors/coverage/elastic-security-alerts.yaml"));
    expect(await runWith(conn, broker)).toMatchObject({ status: "success", requests: 3, recordsOk: 130 });
    const e = (await pool.query("select type, severity, attributes from events where source_id = 'es000003'")).rows[0];
    expect(e.type).toBe("Unusual Login");
    expect(e.severity).toBe("critical");
    expect(e.attributes['_source["host.name"]']).toBe("host-3");
  });

  it("all sources land in the same three tables", async () => {
    for (const f of ["crowdstrike-devices", "fortigate-devices", "netskope-alerts", "elastic-security-alerts"]) {
      const { conn, broker } = await setup(read(`connectors/coverage/${f}.yaml`));
      await runWith(conn, broker);
    }
    const devices = (await pool.query("select source, count(*)::int n from devices group by 1 order by 1")).rows;
    expect(devices).toEqual([{ source: "crowdstrike", n: 230 }, { source: "fortigate", n: 40 }]);
    const events = (await pool.query("select source, count(*)::int n from events group by 1 order by 1")).rows;
    expect(events).toEqual([{ source: "elastic_security", n: 130 }, { source: "netskope", n: 260 }]);
  });
});
