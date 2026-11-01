// Demo rehearsal: the 5-minute breach story in docs/DEMO.md, end to end, on the real broker socket, the API, the job
// queue and the test database, against the mock provider (DPoP required). If a step of the live demo would break,
// this fails first. Each step is the same code path the demo command uses.
import { randomBytes, createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import type { PgBoss } from "pg-boss";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApi } from "../src/api/server.ts";
import { createRemoteBroker, type RemoteBroker } from "../src/broker/remote.ts";
import { createBrokerServer, listenOnSocket } from "../src/broker/server.ts";
import { runConnector } from "../src/engine/runner.ts";
import { RUN_QUEUE, startBoss } from "../src/scheduler/queue.ts";
import { createScheduler } from "../src/scheduler/scheduler.ts";
import { advise } from "../src/security/advisor.ts";
import { incidentState } from "../src/security/incident.ts";
import { panic } from "../src/security/panic.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector } from "../src/store/connectors.ts";
import { closeRunLocks } from "../src/store/runLock.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { verifyReceipt } from "../src/store/staging.ts";
import { buildMock, MOCK_TOKENS, type Mock } from "../mock/server.ts";
import { clearData, hasDb, testUrl } from "./helpers/db.ts";

const fixture = (n: string) => readFileSync(join(import.meta.dirname, "fixtures/configs", n), "utf8");

describe.skipIf(!hasDb)("demo rehearsal: the breach story, end to end", () => {
  let mock: Mock;
  let pool: Pool;
  let brokerPool: Pool;
  let boss: PgBoss;
  let server: ReturnType<typeof createBrokerServer>;
  let remote: RemoteBroker;
  let env: Record<string, string | undefined>;
  const sock = join(tmpdir(), `ixdemo-${process.pid}.sock`);
  const adminSock = join(tmpdir(), `ixdemoa-${process.pid}.sock`);
  const adminToken = randomBytes(16).toString("hex");
  const api = () => buildApi({ pool, env, broker: remote, admin: remote, boss, adminToken: "admin-token-for-test-123456" });
  const run = async (id: string) => (await runConnector({ connector: await loadActiveConnector(pool, id, env), broker: remote, store: createPgRunStore(pool), trigger: "manual" }))[0]!;

  beforeAll(async () => {
    mock = buildMock({ requireDpop: true });
    await mock.app.listen({ host: "127.0.0.1", port: 0 });
    const port = String((mock.app.server.address() as AddressInfo).port);
    env = { ...process.env, MOCK_PORT: port, IX_EGRESS_IPS: "198.51.100.10", IX_CANARY_BASE_URL: "http://localhost:7070" };
    pool = createPool(testUrl("DATABASE_URL_APP"));
    brokerPool = createPool(testUrl("DATABASE_URL_BROKER"));
    await clearData(pool);
    server = createBrokerServer({ pool: brokerPool, masterKey: randomBytes(32), env, adminToken });
    await listenOnSocket(server.app, sock);
    await listenOnSocket(server.adminApp, adminSock);
    remote = createRemoteBroker(sock, { adminSocketPath: adminSock, adminToken });
    boss = await startBoss(testUrl("DATABASE_URL_APP"));
    await boss.deleteAllJobs(RUN_QUEUE);
  }, 60_000);
  afterAll(async () => {
    await boss?.stop({ graceful: false });
    await server?.app.close();
    await server?.adminApp.close();
    await closeRunLocks(pool);
    await Promise.all([pool?.end(), brokerPool?.end()]);
    await mock?.app.close();
  });

  it("runs the whole demo", async () => {
    // ── 1. It works: two Okta-like connectors, one config file each; data verified before it's published ──
    for (const f of ["mock-okta-dpop.yaml", "mock-okta-logs.yaml"]) await remote.register(fixture(f), "add", "demo");
    await remote.putSecret("demo", "mock_client_id", MOCK_TOKENS.clientId);
    await remote.putSecret("demo", "mock_client_secret", MOCK_TOKENS.clientSecret);
    await remote.putSecret("demo", "mock_ssws", MOCK_TOKENS.ssws);
    const users = await run("mock-okta-dpop");
    expect(users).toMatchObject({ status: "success", decision: "verified", published: 450 });
    const logs = await run("mock-okta-logs");
    expect(logs).toMatchObject({ status: "success", decision: "verified" });
    expect(logs.detections).toBeUndefined(); // only the hub's own IP so far
    const caps = (await api().inject({ url: "/v1/capabilities" })).json().connectors.find((c: { id: string }) => c.id === "mock-okta-dpop").capabilities;
    expect([caps.token_binding.status, caps.ip_allowlist.status, caps.staged_integrity.status]).toEqual(["enforced", "enforced", "enforced"]);

    // ── 2. Plant decoys ──
    await remote.createCanary({ ref: "okta_admin_token", prefix: "00" });
    const hook = await remote.createCanary({ ref: "slack_webhook_prod", kind: "url" });

    // ── 3. The breach: the attacker dumps the hub and steals an access token. DPoP: it's useless elsewhere ──
    const stolen = (await (await fetch(`http://localhost:${env.MOCK_PORT}/__dpop/stolen`)).json()).token as string;
    const usersApi = `http://localhost:${env.MOCK_PORT}/api/v1/users?limit=5`;
    expect((await fetch(usersApi, { headers: { authorization: `Bearer ${stolen}` } })).status).toBe(401);
    const k = await generateKeyPair("ES256");
    const proof = await new SignJWT({ htm: "GET", htu: `http://localhost:${env.MOCK_PORT}/api/v1/users`, jti: randomUUID(), ath: createHash("sha256").update(stolen).digest("base64url") })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(k.publicKey) }).setIssuedAt().sign(k.privateKey);
    expect((await fetch(usersApi, { headers: { authorization: `DPoP ${stolen}`, dpop: proof } })).status).toBe(401);

    // ── 4. They try a looted webhook URL: the canary fires, with their IP; incident mode turns on ──
    const res = await api().inject({ method: "POST", url: new URL(hook.value).pathname, payload: { text: "hi" }, headers: { "user-agent": "python-requests/2.32" } });
    expect(res.statusCode).toBe(403);
    expect((await incidentState(pool)).active).toBe(true);
    const health = (await api().inject({ url: "/v1/health" })).json();
    expect(health.security.canary_alerts[0].message).toMatch(/slack_webhook_prod was USED OUTSIDE the hub/);

    // ── 5. Incident mode: the audit-log connector is pulled in, and Okta's own log shows our client from a foreign IP ──
    const tick = await createScheduler({ pool, boss, env }).tick();
    expect(tick.fast).toEqual(["mock-okta-logs"]);
    expect(tick.enqueued).toContain("mock-okta-logs");
    await fetch(`http://localhost:${env.MOCK_PORT}/__attack?ip=203.0.113.7`);
    const logs2 = await run("mock-okta-logs");
    expect(logs2.detections).toEqual([expect.objectContaining({ rule: "hub OAuth client used from outside the hub", ips: { "203.0.113.7": 4 } })]);

    // ── 6. The advisor (rules; Claude explains when a key is set): kill switch, with the evidence ──
    const adv = await advise(pool, { ai: false });
    expect(adv.recommendation).toBe("kill_switch");
    expect(adv.findings.filter((f) => f.severity === "critical").map((f) => f.scope).sort()).toEqual(["credential store", "mock-okta-logs"]);

    // ── 7. Kill switch: everything disabled, the OAuth token revoked at the provider ──
    const p = await panic(pool, { admin: remote, boss, actor: "demo", env });
    expect(p.disabled.sort()).toEqual(["mock-okta-dpop", "mock-okta-logs"]);
    expect(p.broker.tokens_revoked).toBe(1);
    expect(mock.oauth.revoked).toBe(1);
    expect(p.checklist.find((c) => c.connector_id === "mock-okta-dpop")?.action).toBe("revoked_by_api");
    await expect(remote.request({ connectorId: "mock-okta-dpop", method: "GET", url: usersApi })).rejects.toThrow(/disabled/);

    // ── 8. Evidence: every sync has an anchored receipt that still verifies ──
    const receipts = (await pool.query("select id from sync_receipts order by id")).rows.map((r) => Number(r.id));
    expect(receipts.length).toBe(3);
    for (const id of receipts) expect(await verifyReceipt(pool, id)).toMatchObject({ digestMatches: true, anchored: true, anchorMatches: true });
    expect((await remote.verifyLedger()).ok).toBe(true);
  }, 60_000);
});
