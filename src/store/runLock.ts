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
// Writes happen ON the lock-holding session (tx()). Page commits and the final status-plus-watermark transaction run
// on the same connection that holds the lock. PostgreSQL releases a session advisory lock only when that session
// ends, and ending a session rolls back any transaction still open on it. So a run's write either commits while it
// still holds the lock, before any replacement can take it, or not at all. There is no gap between "checked the
// lock" and "committed": a replacement can only get the lock after the old session, and its open transaction, are gone.
//
// check() pings the lock session before every provider request: an early stop, not the safety mechanism.
import { createHash } from "node:crypto";
import pg from "pg";
import { log } from "../log.ts";

/** Advisory lock key for a connector: first 8 bytes of sha256("ix-run:" + id), as a signed bigint. */
export function runLockKey(connectorId: string): string {
  return createHash("sha256").update(`ix-run:${connectorId}`).digest().readBigInt64BE(0).toString();
}

export type RunLock = {
  connectorId: string;
  /** Backend pid of the session holding the lock (diagnostics, tests). */
  pid: number;
  key: string;
  /** Throws LockLost if the lock's session is gone. Early warning only. */
  check(): Promise<void>;
  /**
   * Run fn in a transaction on the lock-holding session. Throws LockLost (nothing committed) if the session is gone
   * before or during it; any other error rolls back and is rethrown as is.
   */
  tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T>;
  release(): Promise<void>;
};

export class LockLost extends Error {}

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
    async tx(fn) {
      const gone = () => new LockLost(`run lock for ${connectorId} was lost (its database session ended); nothing was committed`);
      if (released || lost) throw gone();
      try {
        await client.query("begin");
      } catch {
        lost = true;
        throw gone();
      }
      try {
        const out = await fn(client);
        await client.query("commit");
        return out;
      } catch (e) {
        // A failed COMMIT on a dead session means PostgreSQL rolled it back. If even ROLLBACK fails, the session is
        // gone: report lock loss. Otherwise it was an ordinary error (bad data, a test hook): rolled back, rethrown.
        try {
          await client.query("rollback");
        } catch {
          lost = true;
        }
        if (lost) throw gone();
        throw e;
      }
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
