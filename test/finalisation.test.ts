// Run finalisation and lock loss against the real test database.
//   - The success status and the new watermark are committed in one transaction: if it fails, neither is saved.
//   - A run's writes are transactions on its lock-holding session. If that session is terminated while a write is
//     open (after its statements, before COMMIT), PostgreSQL rolls it back; a replacement run that then takes the
//     lock is the only one whose records, checkpoint and watermark remain. Deterministic: the old transaction is
//     paused at a hook just before COMMIT while the test kills its session and runs the replacement.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { Broker } from "../src/broker/types.ts";
import { runConnector } from "../src/engine/runner.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector, registerConnector } from "../src/store/connectors.ts";
import { closeRunLocks, runLockKey } from "../src/store/runLock.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { clearData, hasDb, regPool, testUrl } from "./helpers/db.ts";

const ID = "fin-logs";
const YAML = `apiVersion: ix/v1
kind: Connector
metadata: { id: ${ID}, source: fin, tenant: demo }
connection: { base_url: "http://localhost:1", auth: { type: none } }
streams:
  - name: logs
    entity: event
    request: { method: GET, path: /logs }
    records_path: $
    pagination: { type: none }
    incremental: { cursor_field: published, param: since, template: "{{cursor}}", initial: "2026-01-01T00:00:00Z" }
    mapping:
      id: { path: uuid, required: true }
      type: { const: login }
      timestamp: { path: published, transform: to_iso8601 }
policy: { allowed_hosts: [localhost], max_requests_per_run: 5 }
`;
const ev = (id: string, day: number) => ({ uuid: id, published: `2026-02-0${day}T00:00:00.000Z` });

function broker(records: () => unknown[], gate?: Promise<void>, entered?: () => void) {
  const calls: URL[] = [];
  const b: Broker = {
    async request(req) {
      calls.push(new URL(req.url));
      entered?.();
      if (gate) await gate;
      return { status: 200, headers: {}, body: JSON.stringify(records()), durationMs: 1, retries: 0, rateLimitedMs: 0 };
    },
    async credentialInfo() {
      return {};
    },
  };
  return { b, calls };
}

describe.skipIf(!hasDb)("run finalisation and lock loss", () => {
  let poolA: Pool;
  let poolB: Pool;
  let adminPool: Pool;
  const one = async (sql: string, v: unknown[] = []) => (await poolA.query(sql, v)).rows[0];
  const lockHolderPid = async () => {
    const k = BigInt(runLockKey(ID));
    return (
      await adminPool.query(
        "select pid from pg_locks where locktype = 'advisory' and granted and classid = $1::bigint::oid and objid = $2::bigint::oid and objsubid = 1",
        [BigInt.asUintN(32, k >> 32n).toString(), BigInt.asUintN(32, k).toString()],
      )
    ).rows[0]?.pid as number | undefined;
  };

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
    await registerConnector(regPool(), YAML, { env: {} });
  });

  it("the final transaction fails: neither the success status nor the new watermark is committed", async () => {
    const conn = await loadActiveConnector(poolA, ID, {});
    const p = broker(() => [ev("a", 1), ev("b", 3)]);
    // The final transaction (status + watermark, on the lock session) fails just before COMMIT and is rolled back.
    const store = createPgRunStore(poolA, {
      beforeCommit: async (kind) => {
        if (kind === "finish") throw new Error("simulated failure before COMMIT");
      },
    });
    await expect(runConnector({ connector: conn, broker: p.b, store })).rejects.toThrow(/simulated failure before COMMIT/);

    expect(await one("select status from runs where connector_id = $1", [ID])).toEqual({ status: "running" }); // not success
    expect((await one("select cursor_value from checkpoints where connector_id = $1", [ID]))?.cursor_value ?? null).toBeNull(); // not advanced
    expect(Number((await one("select count(*) from events where connector_id = $1", [ID])).count)).toBe(2); // pages committed before

    // The next run asks for the same window again and then advances, in one transaction with its success.
    const [r] = await runConnector({ connector: conn, broker: p.b, store: createPgRunStore(poolA) });
    expect(p.calls.map((u) => u.searchParams.get("since"))).toEqual(["2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z"]);
    expect(r).toMatchObject({ status: "success", watermark: "2026-02-03T00:00:00.000Z" });
    expect((await one("select cursor_value from checkpoints where connector_id = $1", [ID])).cursor_value).toBe("2026-02-03T00:00:00.000Z");
  });

  it("lock lost mid-run: the original run commits nothing more and saves no watermark; the new holder runs normally", async () => {
    const conn = await loadActiveConnector(poolA, ID, {});
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    let entered!: () => void;
    const inFlight = new Promise<void>((r) => (entered = r));
    const first = runConnector({ connector: conn, broker: broker(() => [ev("from-old-run", 5)], gate, entered).b, store: createPgRunStore(poolA) });
    await inFlight; // the first run holds the lock and is waiting on the provider

    const pid = await lockHolderPid();
    expect(pid).toBeTypeOf("number");
    await adminPool.query("select pg_terminate_backend($1)", [pid]); // its lock session dies

    // Another run takes the lock and completes while the first one is still in flight.
    let second;
    for (let i = 0; i < 50 && !second; i++) {
      second = await runConnector({ connector: conn, broker: broker(() => [ev("from-new-run", 2)]).b, store: createPgRunStore(poolB) }).catch(() => undefined);
      if (!second) await new Promise((r) => setTimeout(r, 20));
    }
    expect(second?.[0]).toMatchObject({ status: "success", watermark: "2026-02-02T00:00:00.000Z" });

    open(); // the first run's provider answers now
    const [r1] = await first;
    expect(r1).toMatchObject({ status: "failed", lastError: expect.stringMatching(/run lock lost/) });
    expect(r1?.watermark).toBeUndefined();

    const ids = (await poolA.query("select source_id from events where connector_id = $1 order by 1", [ID])).rows.map((r) => r.source_id);
    expect(ids).toEqual(["from-new-run"]); // nothing from the run that lost its lock
    expect((await one("select cursor_value from checkpoints where connector_id = $1", [ID])).cursor_value).toBe("2026-02-02T00:00:00.000Z");
  });

  it("lock already lost at finalisation: no watermark, and only the run's own history row is marked failed", async () => {
    const store = createPgRunStore(poolA);
    const lock = await store.lockConnector!(ID);
    expect(lock).not.toBeNull();
    const runId = "00000000-0000-4000-8000-000000000001";
    await store.startRun({ runId, connectorId: ID, stream: "logs", configHash: "x", startedAt: new Date(), resumed: false, trigger: "manual" });
    await adminPool.query("select pg_terminate_backend($1)", [await lockHolderPid()]);
    await new Promise((r) => setTimeout(r, 50));

    const done = await store.finishRun({
      runId, connectorId: ID, stream: "logs", status: "success", requests: 1, retries: 0, rateLimitedMs: 0,
      fieldStats: { records: 1, hits: {} }, watermark: "2026-03-01T00:00:00.000Z",
    });
    expect(done).toMatchObject({ status: "failed", watermarkSaved: false, lastError: expect.stringMatching(/run lock lost.*watermark not advanced/) });
    expect(await one("select last_success_at from connectors where id = $1", [ID])).toEqual({ last_success_at: null });
    expect(await one("select status from runs where id = $1", [runId])).toEqual({ status: "failed" });
    expect(await one("select cursor_value from checkpoints where connector_id = $1", [ID])).toBeUndefined();
    await expect(lock!.check()).rejects.toThrow(/run lock lost/);
    await lock!.release(); // destroys the dead connection; no throw
  });

  /** Old run paused inside a write transaction on its lock session; returns controls for the test. */
  async function pausedOldRun(kind: "page" | "finish", oldRecords: unknown[]) {
    const conn = await loadActiveConnector(poolA, ID, {});
    let paused!: () => void;
    const atCommit = new Promise<void>((r) => (paused = r));
    let resume!: () => void;
    const gate = new Promise<void>((r) => (resume = r));
    const store = createPgRunStore(poolA, {
      beforeCommit: async (k) => {
        if (k !== kind) return;
        paused();
        await gate; // writes are done, COMMIT not sent yet
      },
    });
    const result = runConnector({ connector: conn, broker: broker(() => oldRecords).b, store });
    await atCommit;
    return { conn, result, resume };
  }
  async function replacementRun(conn: Awaited<ReturnType<typeof loadActiveConnector>>, records: unknown[]) {
    for (let i = 0; i < 100; i++) {
      const r = await runConnector({ connector: conn, broker: broker(() => records).b, store: createPgRunStore(poolB) }).catch((e) => {
        if (/already running/.test((e as Error).message)) return undefined;
        throw e;
      });
      if (r) return r;
      await new Promise((res) => setTimeout(res, 20));
    }
    throw new Error("replacement never got the lock");
  }

  it("old lock session killed during a page commit (writes done, COMMIT pending): rolled back; only the replacement remains", async () => {
    const old = await pausedOldRun("page", [ev("old-1", 8), ev("old-2", 9)]);
    // The old transaction's rows are written but uncommitted: invisible to everyone else.
    expect(Number((await one("select count(*) from events where connector_id = $1", [ID])).count)).toBe(0);
    const pid = await lockHolderPid();
    await adminPool.query("select pg_terminate_backend($1)", [pid]);

    const [rep] = await replacementRun(old.conn, [ev("new-1", 2)]);
    expect(rep).toMatchObject({ status: "success", watermark: "2026-02-02T00:00:00.000Z" });

    old.resume(); // the old run tries to COMMIT on its dead session
    const [o] = await old.result;
    expect(o).toMatchObject({ status: "failed", lastError: expect.stringMatching(/run lock lost/) });
    expect(o?.watermark).toBeUndefined();

    expect((await poolA.query("select source_id from events where connector_id = $1 order by 1", [ID])).rows.map((r) => r.source_id)).toEqual(["new-1"]);
    expect(await one("select cursor_value, page_state from checkpoints where connector_id = $1", [ID])).toEqual({ cursor_value: "2026-02-02T00:00:00.000Z", page_state: null });
    const runRows = (await poolA.query("select status, records_ok from runs where connector_id = $1 order by started_at", [ID])).rows;
    expect(runRows).toEqual([{ status: "failed", records_ok: 0 }, { status: "success", records_ok: 1 }]); // old page's counters rolled back too
  });

  it("old lock session killed during finalisation (status + watermark written, COMMIT pending): rolled back; the replacement's watermark stands", async () => {
    // The old run's page committed while it held the lock; its finalisation (success + watermark day 9) is pending.
    const old = await pausedOldRun("finish", [ev("old-1", 9)]);
    await adminPool.query("select pg_terminate_backend($1)", [await lockHolderPid()]);

    const [rep] = await replacementRun(old.conn, [ev("new-1", 2)]);
    expect(rep).toMatchObject({ status: "success", watermark: "2026-02-02T00:00:00.000Z" });

    old.resume();
    const [o] = await old.result;
    expect(o).toMatchObject({ status: "failed", lastError: expect.stringMatching(/run lock lost.*watermark not advanced/) });
    // Day 9 never landed: the only watermark is the replacement's.
    expect((await one("select cursor_value from checkpoints where connector_id = $1", [ID])).cursor_value).toBe("2026-02-02T00:00:00.000Z");
    const statuses = (await poolA.query("select status from runs where connector_id = $1 order by started_at", [ID])).rows.map((r) => r.status);
    expect(statuses).toEqual(["failed", "success"]);
  });
});
