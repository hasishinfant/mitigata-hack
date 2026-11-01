// Single-flight execution: at most one run per connector at a time, across every process that executes runs
// (worker, `ix run`, and anything added later such as abandoned-run recovery), via a PostgreSQL advisory lock.
//
// Session-level, not transaction-level: a run spans many transactions and network calls, so the lock is held
// on one dedicated connection for the run's whole lifetime and released in `finally`, before that connection
// goes back to its pool. If the process dies, PostgreSQL drops the session and the lock with it.
//
// Lock connections come from their own small pool, never the data pool: with N concurrent runs each holding a lock
// connection and also needing data connections for page commits, a shared pool of size <= N would deadlock.
//
// Lock loss fails closed. If the lock's session dies mid-run (database restart, network, terminated backend), another
// run may take the lock, so the original run must stop:
//   - check() runs before every provider request: it pings the lock session and throws if it is gone;
//   - every page-commit transaction (and the final watermark write) re-checks in pg_locks that the lock is still
//     granted to this run's session, and aborts if not (see fenceQuery).
// Residual window: the time between that fence check and the COMMIT of the same transaction (milliseconds; a new
// run would also have to take the lock and fetch a page from the provider inside it).
import { createHash } from "node:crypto";
import pg from "pg";
import { log } from "../log.ts";

/** Advisory lock key for a connector: first 8 bytes of sha256("ix-run:" + id), as a signed bigint. */
export function runLockKey(connectorId: string): string {
  return createHash("sha256").update(`ix-run:${connectorId}`).digest().readBigInt64BE(0).toString();
}

export type RunLock = {
  connectorId: string;
  /** Backend pid of the session holding the lock (for the commit-time fence). */
  pid: number;
  key: string;
  /** Throws LockLost if the lock's session is gone. */
  check(): Promise<void>;
  release(): Promise<void>;
};

export class LockLost extends Error {}

/**
 * SQL that returns a row only while `pid` still holds the advisory lock `key` (granted, session-level).
 * pg_locks shows a bigint advisory key as classid = high 32 bits, objid = low 32 bits, objsubid = 1.
 */
export function fenceQuery(lock: Pick<RunLock, "pid" | "key">): { text: string; values: unknown[] } {
  const k = BigInt(lock.key);
  return {
    text: `select 1 from pg_locks where locktype = 'advisory' and granted and pid = $1
           and classid = $2::bigint::oid and objid = $3::bigint::oid and objsubid = 1`,
    values: [lock.pid, BigInt.asUintN(32, k >> 32n).toString(), BigInt.asUintN(32, k).toString()],
  };
}

const lockPools = new WeakMap<pg.Pool, pg.Pool>();
function lockPoolFor(data: pg.Pool): pg.Pool {
  let p = lockPools.get(data);
  if (!p) {
    p = new pg.Pool({ ...data.options, max: 32, idleTimeoutMillis: 10_000, allowExitOnIdle: true });
    p.on("error", (e) => log.warn({ err: e.message }, "run lock pool: idle connection error"));
    lockPools.set(data, p);
  }
  return p;
}

/** Close the lock pool that belongs to a data pool (process shutdown, tests). */
export async function closeRunLocks(data: pg.Pool): Promise<void> {
  const p = lockPools.get(data);
  lockPools.delete(data);
  await p?.end();
}

/**
 * Try to take the connector's run lock without waiting. Returns null if another session holds it.
 * The returned lock must be released (in finally).
 */
export async function acquireRunLock(data: pg.Pool, connectorId: string): Promise<RunLock | null> {
  const key = runLockKey(connectorId);
  const client = await lockPoolFor(data).connect();
  let lost = false;
  const onError = (e: Error) => {
    lost = true;
    log.error({ connector: connectorId, err: e.message }, "run lock connection lost: single-flight no longer guaranteed for this run");
  };
  client.on("error", onError);
  let got: boolean;
  let pid: number;
  try {
    const r = await client.query("select pg_try_advisory_lock($1::bigint) as ok, pg_backend_pid() as pid", [key]);
    got = r.rows[0].ok as boolean;
    pid = r.rows[0].pid as number;
  } catch (e) {
    client.off("error", onError);
    client.release(true);
    throw e;
  }
  if (!got) {
    client.off("error", onError);
    client.release();
    return null;
  }
  let released = false;
  return {
    connectorId,
    pid,
    key,
    async check() {
      if (released) throw new LockLost(`run lock for ${connectorId} was already released`);
      if (!lost) {
        try {
          await client.query("select 1"); // the session is alive, so the session-level lock is still ours
          return;
        } catch {
          lost = true;
        }
      }
      throw new LockLost(`run lock for ${connectorId} was lost (its database session ended); stopping this run`);
    },
    async release() {
      if (released) return;
      released = true;
      try {
        if (lost) throw new Error("connection lost");
        const still = (await client.query("select pg_advisory_unlock($1::bigint) as ok", [key])).rows[0].ok as boolean;
        if (!still) log.warn({ connector: connectorId }, "run lock was not held at release (connection was reset during the run)");
        client.off("error", onError);
        client.release();
      } catch {
        // Can't unlock cleanly: destroy the connection, which ends the session and drops any lock it still holds.
        client.off("error", onError);
        client.release(true);
      }
    },
  };
}
