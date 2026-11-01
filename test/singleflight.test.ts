// Single-flight execution against the real test database: PostgreSQL session advisory locks, real concurrent runs.
// The provider stub blocks until the test releases it, so a run is provably mid-flight (holding its lock)
// while the second invocation tries to start.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { BrokerError, type Broker } from "../src/broker/types.ts";
import { ConnectorBusy, runConnector } from "../src/engine/runner.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector, registerConnector } from "../src/store/connectors.ts";
import { acquireRunLock, closeRunLocks, runLockKey } from "../src/store/runLock.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { createWorker } from "../src/worker/worker.ts";
import { clearData, hasDb, regPool, testUrl } from "./helpers/db.ts";

const env = { MOCK_PORT: "1" };
const yaml = (id: string) =>
  readFileSync(join(import.meta.dirname, "fixtures/configs/mock-github-members.yaml"), "utf8").replace("id: mock-github-members", `id: ${id}`);

/** A provider that holds every request until open() is called. `entered` resolves once `expect` requests are in flight. */
function gatedBroker(expectInFlight = 1, fail?: () => Error) {
  let open!: () => void;
  const gate = new Promise<void>((r) => (open = r));
  let inFlight = 0;
  let maxInFlight = 0;
  let entered!: () => void;
  const enteredP = new Promise<void>((r) => (entered = r));
  const broker: Broker = {
    async request() {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      if (inFlight >= expectInFlight) entered();
      await gate;
      inFlight--;
      if (fail) throw fail();
      return { status: 200, headers: {}, body: "[]", durationMs: 1, retries: 0, rateLimitedMs: 0 };
    },
    async credentialInfo() {
      return {};
    },
  };
  return { broker, open: () => open(), entered: enteredP, maxInFlight: () => maxInFlight };
}

describe.skipIf(!hasDb)("single-flight runs (PostgreSQL advisory locks)", () => {
  // Two pools stand in for two processes: separate connections, separate sessions.
  let poolA: Pool;
  let poolB: Pool;
  let adminPool: Pool;
  const runs = async (id: string) => Number((await poolA.query("select count(*) from runs where connector_id = $1", [id])).rows[0].count);

  beforeAll(() => {
    poolA = createPool(testUrl("DATABASE_URL_APP"));
    poolB = createPool(testUrl("DATABASE_URL_APP"));
    adminPool = createPool(testUrl("DATABASE_URL_ADMIN"));
  });
  afterAll(async () => {
    await Promise.all([closeRunLocks(poolA), closeRunLocks(poolB)]);
    await Promise.all([poolA?.end(), poolB?.end(), adminPool?.end()]);
  });
  beforeEach(async () => {
    await clearData(poolA);
    for (const id of ["sf-one", "sf-two"]) await registerConnector(regPool(), yaml(id), { env });
  });

  it("CLI and worker, same connector: only one run acquires the lock; the other is refused cleanly", async () => {
    const g = gatedBroker();
    const worker = createWorker({ pool: poolA, broker: g.broker, env });
    const running = worker.handle({ connectorId: "sf-one", trigger: "schedule" });
    await g.entered; // the worker's run is mid-flight, lock held

    // What `ix run sf-one` does, from another process (another pool, another session).
    const conn = await loadActiveConnector(poolB, "sf-one", env);
    const cli = runConnector({ connector: conn, broker: gatedBroker().broker, store: createPgRunStore(poolB), trigger: "manual" });
    await expect(cli).rejects.toBeInstanceOf(ConnectorBusy);
    await expect(cli).rejects.toThrow(/sf-one is already running/);

    g.open();
    const [r] = await running;
    expect(r).toMatchObject({ status: "success" });
    expect(await runs("sf-one")).toBe(1); // the refused invocation wrote nothing
  });

  it("two workers, same connector: only one proceeds; the other skips the job", async () => {
    const g = gatedBroker();
    const w1 = createWorker({ pool: poolA, broker: g.broker, env });
    const w2 = createWorker({ pool: poolB, broker: gatedBroker().broker, env });
    const first = w1.handle({ connectorId: "sf-one", trigger: "schedule" });
    await g.entered;
    expect(await w2.handle({ connectorId: "sf-one", trigger: "api" })).toEqual([]); // skipped, not run
    g.open();
    expect((await first)[0]?.status).toBe("success");
    expect(await runs("sf-one")).toBe(1);
  });

  it("different connectors run concurrently", async () => {
    const g = gatedBroker(2); // `entered` only resolves once both runs have a request in flight at the same time
    const w1 = createWorker({ pool: poolA, broker: g.broker, env });
    const w2 = createWorker({ pool: poolB, broker: g.broker, env });
    const a = w1.handle({ connectorId: "sf-one", trigger: "schedule" });
    const b = w2.handle({ connectorId: "sf-two", trigger: "schedule" });
    await g.entered;
    expect(g.maxInFlight()).toBe(2);
    g.open();
    expect((await a)[0]?.status).toBe("success");
    expect((await b)[0]?.status).toBe("success");
  });

  it("a failed run releases the lock; so does a run that throws before starting", async () => {
    const g = gatedBroker(1, () => new BrokerError("network", "network error: ECONNRESET"));
    g.open();
    const conn = await loadActiveConnector(poolA, "sf-one", env);
    const [r] = await runConnector({ connector: conn, broker: g.broker, store: createPgRunStore(poolA) });
    expect(r?.status).toBe("failed");
    const after = await acquireRunLock(poolB, "sf-one");
    expect(after).not.toBeNull();
    await after!.release();

    await poolA.query("update connectors set status = 'disabled' where id = 'sf-one'");
    await expect(runConnector({ connector: conn, broker: g.broker, store: createPgRunStore(poolA) })).rejects.toThrow(/disabled/);
    const again = await acquireRunLock(poolB, "sf-one");
    expect(again).not.toBeNull();
    await again!.release();
  });

  it("holder crashes: PostgreSQL drops the session and its lock; the next run can start", async () => {
    const held = await acquireRunLock(poolA, "sf-one");
    expect(held).not.toBeNull();
    expect(await acquireRunLock(poolB, "sf-one")).toBeNull(); // held by another session

    // The worker process dies: its database session is terminated.
    await adminPool.query("select pg_terminate_backend($1)", [held!.pid]);
    let next = null;
    for (let i = 0; i < 50 && !next; i++) {
      next = await acquireRunLock(poolB, "sf-one");
      if (!next) await new Promise((r) => setTimeout(r, 20));
    }
    expect(next).not.toBeNull();
    await next!.release();
    await held!.release(); // the dead connection is destroyed, not returned to the pool; no throw
    // And a real run works afterwards.
    const conn = await loadActiveConnector(poolA, "sf-one", env);
    const g = gatedBroker();
    g.open();
    expect((await runConnector({ connector: conn, broker: g.broker, store: createPgRunStore(poolA) }))[0]?.status).toBe("success");
  });

  it("the lock is session-scoped: it survives the run's own transactions", async () => {
    const held = await acquireRunLock(poolA, "sf-one");
    // Page commits run in their own transactions on other connections; none of them ends the lock.
    for (let i = 0; i < 3; i++) await poolA.query("begin; select 1; commit;");
    expect(await acquireRunLock(poolB, "sf-one")).toBeNull();
    await held!.release();
    const free = await acquireRunLock(poolB, "sf-one");
    expect(free).not.toBeNull();
    await free!.release();
  });

  it("lock keys are per connector and stable", () => {
    expect(runLockKey("sf-one")).toBe(runLockKey("sf-one"));
    expect(runLockKey("sf-one")).not.toBe(runLockKey("sf-two"));
    expect(runLockKey("sf-one")).toMatch(/^-?\d+$/);
  });
});
