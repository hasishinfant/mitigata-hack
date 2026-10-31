// Phase 5: scheduler (due computation, dedupe, pause handling), worker via the real pg-boss queue,
// health derivation, and the API + dashboard.
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import type { PgBoss } from "pg-boss";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApi } from "../src/api/server.ts";
import type { BrokerAdmin } from "../src/broker/remote.ts";
import { envSecretSource } from "../src/broker/secrets.ts";
import { enqueueRun, RUN_QUEUE, startBoss, type RunJob } from "../src/scheduler/queue.ts";
import { createScheduler, nextRunAt } from "../src/scheduler/scheduler.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { registerConnector } from "../src/store/connectors.ts";
import { deriveHealth } from "../src/store/health.ts";
import { createWorker } from "../src/worker/worker.ts";
import { buildMock, MOCK_TOKENS, type Mock } from "../mock/server.ts";
import { clearData, hasDb, regPool, testUrl } from "./helpers/db.ts";

const fixture = (name: string) => readFileSync(join(import.meta.dirname, "fixtures/configs", name), "utf8");
const ADMIN = "test-admin-token-abcdef";

describe("health derivation", () => {
  const now = Date.parse("2026-10-31T12:00:00Z");
  const base = { status: "enabled", configOk: true, lastSuccessAt: "2026-10-31T11:59:00Z", now };
  it("maps run states to health words", () => {
    expect(deriveHealth({ ...base, latest: [] })).toBe("never_run");
    expect(deriveHealth({ ...base, latest: [{ status: "success" }] })).toBe("healthy");
    expect(deriveHealth({ ...base, latest: [{ status: "success" }, { status: "partial" }] })).toBe("warning");
    expect(deriveHealth({ ...base, latest: [{ status: "degraded" }] })).toBe("degraded");
    expect(deriveHealth({ ...base, latest: [{ status: "success" }, { status: "auth_failed" }] })).toBe("failing");
    expect(deriveHealth({ ...base, latest: [{ status: "running" }] })).toBe("running");
    expect(deriveHealth({ ...base, status: "paused", latest: [{ status: "failed" }] })).toBe("paused");
    expect(deriveHealth({ ...base, configOk: false, latest: [] })).toBe("config_error");
  });
  it("stale when no success for 3 schedule intervals", () => {
    const old = { ...base, lastSuccessAt: "2026-10-31T08:00:00Z", latest: [{ status: "success" }] };
    expect(deriveHealth({ ...old, everyMs: 3_600_000 })).toBe("stale");
    expect(deriveHealth({ ...old, everyMs: 6 * 3_600_000 })).toBe("healthy");
  });
  it("nextRunAt adds every + bounded jitter", () => {
    expect(nextRunAt(0, 60_000, 10_000, () => 0).getTime()).toBe(60_000);
    expect(nextRunAt(0, 60_000, 10_000, () => 0.999).getTime()).toBe(69_990);
  });
});

describe.skipIf(!hasDb)("scheduler, worker, API", () => {
  let mock: Mock;
  let pool: Pool;
  let boss: PgBoss;
  let env: Record<string, string | undefined>;
  let t: number;

  beforeAll(async () => {
    mock = buildMock();
    await mock.app.listen({ host: "127.0.0.1", port: 0 });
    env = { ...process.env, MOCK_PORT: String((mock.app.server.address() as AddressInfo).port) };
    pool = createPool(testUrl("DATABASE_URL_APP"));
    boss = await startBoss(testUrl("DATABASE_URL_APP"));
  }, 60_000);
  afterAll(async () => {
    await boss?.stop({ graceful: false });
    await pool?.end();
    await mock?.app.close();
  });
  beforeEach(async () => {
    await clearData(pool);
    await boss.deleteAllJobs(RUN_QUEUE);
    t = Date.parse("2026-10-31T12:00:00Z");
  });

  const scheduler = () => createScheduler({ pool, boss, now: () => t, random: () => 0, env });
  const register = (name: string) => registerConnector(regPool(), fixture(name), { env });
  const queued = async () => (await pool.query("select data->>'connectorId' as id, data->>'trigger' as trigger, state from pgboss.job where name = $1 order by 1", [RUN_QUEUE])).rows;

  it("enqueues due connectors once, then waits for the interval", async () => {
    await register("mock-github-members.yaml"); // every 1h
    await register("mock-nvd-cves.yaml"); // every 6h
    const r1 = await scheduler().tick();
    expect(r1.enqueued.sort()).toEqual(["mock-github-members", "mock-nvd-cves"]);
    expect((await queued()).map((j) => j.id)).toEqual(["mock-github-members", "mock-nvd-cves"]);

    expect((await scheduler().tick()).enqueued).toEqual([]); // same instant: nothing due
    t += 61 * 60_000; // 61 minutes later: only the hourly one is due, but its first job is still queued
    const r3 = await scheduler().tick();
    expect(r3.enqueued).toEqual([]);
    expect(r3.skipped).toContainEqual({ id: "mock-github-members", reason: "previous run still queued or running" });
    const next = (await pool.query("select id, next_run_at from connectors order by id")).rows;
    expect(next[0].next_run_at).toBe(new Date(t + 3_600_000).toISOString());
    expect(next[1].next_run_at).toBe(new Date(Date.parse("2026-10-31T12:00:00Z") + 6 * 3_600_000).toISOString());
  });

  it("exclusive queue: a manual run can't double up with a queued one", async () => {
    await register("mock-github-members.yaml");
    expect(await enqueueRun(boss, { connectorId: "mock-github-members", trigger: "api" })).toBeTruthy();
    expect(await enqueueRun(boss, { connectorId: "mock-github-members", trigger: "schedule" })).toBeNull();
  });

  it("skips paused connectors until the cool-down ends, and connectors without a schedule", async () => {
    await register("mock-github-members.yaml");
    const until = new Date(t + 5 * 60_000);
    await pool.query("update connectors set status = 'paused', paused_until = $1", [until]);
    const r = await scheduler().tick();
    expect(r.enqueued).toEqual([]);
    expect(r.skipped).toEqual([{ id: "mock-github-members", reason: "circuit open" }]);
    expect((await pool.query("select next_run_at from connectors")).rows[0].next_run_at).toBe(until.toISOString());

    await registerConnector(regPool(), fixture("mock-okta-users.yaml").replace("schedule: { every: 15m }\n", ""), { env });
    expect((await scheduler().tick()).skipped).toContainEqual({ id: "mock-okta-users", reason: "no schedule" });
  });

  it("worker runs a scheduled job end to end; run records the trigger", async () => {
    await register("mock-github-members.yaml");
    await scheduler().tick();
    const [job] = await boss.fetch<RunJob>(RUN_QUEUE);
    expect(job!.data).toEqual({ connectorId: "mock-github-members", trigger: "schedule" });
    const worker = createWorker({ pool, secrets: envSecretSource({ IX_SECRET_MOCK_BEARER: MOCK_TOKENS.bearer }), env });
    const [summary] = await worker.handle(job!.data);
    await boss.complete(RUN_QUEUE, job!.id);
    expect(summary).toMatchObject({ status: "success", recordsOk: 250 });
    expect((await pool.query("select status, trigger from runs")).rows).toEqual([{ status: "success", trigger: "schedule" }]);
    // queue is free again
    expect(await enqueueRun(boss, { connectorId: "mock-github-members", trigger: "api" })).toBeTruthy();
  });

  it("worker skips a connector disabled after it was queued", async () => {
    await register("mock-github-members.yaml");
    await pool.query("update connectors set status = 'disabled'");
    const worker = createWorker({ pool, secrets: envSecretSource({}), env });
    expect(await worker.handle({ connectorId: "mock-github-members", trigger: "schedule" })).toEqual([]);
  });

  // ---------- API ----------
  it("GET /v1/health reports status, last run, records pulled and last error (FR-10)", async () => {
    await register("mock-github-members.yaml");
    await register("mock-nvd-cves.yaml");
    const worker = createWorker({ pool, secrets: envSecretSource({ IX_SECRET_MOCK_BEARER: MOCK_TOKENS.bearer, IX_SECRET_MOCK_API_KEY: "wrong-key-000000" }), env });
    await worker.handle({ connectorId: "mock-github-members", trigger: "api" });
    await worker.handle({ connectorId: "mock-nvd-cves", trigger: "api" });
    const app = buildApi({ pool, env });
    const res = await app.inject({ method: "GET", url: "/v1/health" });
    expect(res.statusCode).toBe(200);
    const h = res.json();
    expect(h.summary).toMatchObject({ total: 2, healthy: 1, failing: 1 });
    const gh = h.connectors.find((c: { id: string }) => c.id === "mock-github-members");
    expect(gh).toMatchObject({
      health: "healthy", source: "github", auth_type: "bearer", entities: ["user"], records_in_store: 250, schedule_every: "1h",
      last_run: { status: "success", records_pulled: 250, requests: 3, trigger: "api" }, last_error: null,
    });
    const nvd = h.connectors.find((c: { id: string }) => c.id === "mock-nvd-cves");
    expect(nvd).toMatchObject({ health: "failing", last_error: "HTTP 403: credentials rejected" });
    expect(JSON.stringify(h)).not.toContain("wrong-key-000000");
  });

  it("records, quarantine and runs routes", async () => {
    await register("mock-github-members.yaml");
    await createWorker({ pool, secrets: envSecretSource({ IX_SECRET_MOCK_BEARER: MOCK_TOKENS.bearer }), env }).handle({ connectorId: "mock-github-members", trigger: "api" });
    const app = buildApi({ pool, env });
    const users = (await app.inject({ url: "/v1/records/users?source=github&limit=5" })).json();
    expect(users.total).toBe(250);
    expect(users.rows).toHaveLength(5);
    expect((await app.inject({ url: "/v1/records/secrets" })).statusCode).toBe(404);
    expect((await app.inject({ url: "/v1/records/users?since=yesterday" })).statusCode).toBe(400);
    expect((await app.inject({ url: "/v1/quarantine" })).json()).toEqual({ items: [] });
    expect((await app.inject({ url: "/v1/connectors/mock-github-members/runs" })).json().runs).toHaveLength(1);
  });

  it("POST /v1/configs/validate returns line-numbered errors", async () => {
    const app = buildApi({ pool, env });
    const res = await app.inject({ method: "POST", url: "/v1/configs/validate", headers: { "content-type": "text/yaml" }, payload: fixture("bad-typo.yaml") });
    expect(res.json()).toMatchObject({ ok: false, errors: [{ line: 17, path: "streams[0].mapping.timestamp.trasform" }] });
  });

  it("state-changing routes need the admin token; disabled when no token is configured", async () => {
    const yaml = fixture("mock-github-members.yaml");
    const headers = { "content-type": "text/yaml" };
    expect((await buildApi({ pool, env }).inject({ method: "POST", url: "/v1/connectors", headers, payload: yaml })).statusCode).toBe(503);
    // Stand-in for the broker's registration endpoint (the real one is covered in phase6.test.ts).
    const admin = {
      register: (y: string, mode: "add" | "update") => registerConnector(regPool(), y, { env, mustNotExist: mode === "add", mustExist: mode === "update" }),
    } as unknown as BrokerAdmin;
    const app = buildApi({ pool, env, adminToken: ADMIN, boss, admin });
    expect((await app.inject({ method: "POST", url: "/v1/connectors", headers, payload: yaml })).statusCode).toBe(401);
    expect((await app.inject({ method: "POST", url: "/v1/connectors", headers: { ...headers, authorization: "Bearer nope" }, payload: yaml })).statusCode).toBe(401);
    const auth = { ...headers, authorization: `Bearer ${ADMIN}` };
    expect((await app.inject({ method: "POST", url: "/v1/connectors", headers: auth, payload: yaml })).statusCode).toBe(201);
    expect((await app.inject({ method: "POST", url: "/v1/connectors", headers: auth, payload: yaml })).statusCode).toBe(409);
    const bad = await app.inject({ method: "POST", url: "/v1/connectors", headers: auth, payload: fixture("bad-delete.yaml") });
    expect(bad.statusCode).toBe(422);
    expect(bad.json().errors[0].path).toBe("streams[0].request.method");

    const run1 = await app.inject({ method: "POST", url: "/v1/connectors/mock-github-members/runs", headers: { authorization: `Bearer ${ADMIN}` } });
    expect(run1.statusCode).toBe(202);
    expect(run1.json().queued).toBe(true);
    const run2 = await app.inject({ method: "POST", url: "/v1/connectors/mock-github-members/runs", headers: { authorization: `Bearer ${ADMIN}` } });
    expect(run2.json()).toEqual({ queued: false, reason: "a run is already queued or running" });
    expect((await app.inject({ method: "POST", url: "/v1/connectors/nope/runs", headers: { authorization: `Bearer ${ADMIN}` } })).statusCode).toBe(404);

    // Run now from the dashboard: no token, but only with the dashboard header (blocks cross-site requests).
    await boss.deleteAllJobs(RUN_QUEUE);
    expect((await app.inject({ method: "POST", url: "/v1/connectors/mock-github-members/runs" })).statusCode).toBe(401);
    const dash = await app.inject({ method: "POST", url: "/v1/connectors/mock-github-members/runs", headers: { "x-ix-dashboard": "1" } });
    expect(dash.statusCode).toBe(202);
    expect(dash.json().queued).toBe(true);
    // ...but the kill switch still needs the token.
    expect((await app.inject({ method: "POST", url: "/v1/panic", headers: { "x-ix-dashboard": "1" } })).statusCode).toBe(401);
  });

  it("dashboard is served with a strict CSP and no inline script", async () => {
    const app = buildApi({ pool, env });
    const page = await app.inject({ url: "/" });
    expect(page.statusCode).toBe(200);
    expect(page.headers["content-security-policy"]).toContain("script-src 'self'");
    expect(page.body).not.toMatch(/<script>(?!<\/script>)/);
    expect(page.body).not.toMatch(/\son\w+=/); // no inline event handlers
    expect((await app.inject({ url: "/app.js" })).body).not.toContain("innerHTML");
  });
});
