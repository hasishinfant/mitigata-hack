// Worker: claims queued runs and executes them. One long-lived broker per worker process keeps
// OAuth tokens and rate-limit buckets warm across runs. Configs are reloaded for every job, so
// `ix update` takes effect on the next run.
// Phase 5: the broker is in-process (this process holds the broker DB role + master key).
// Phase 6 replaces createLocalBroker with a socket client and this process loses all secrets.
import type pg from "pg";
import { createLocalBroker } from "../broker/client.ts";
import type { SecretSource } from "../broker/types.ts";
import type { ResolvedConnector } from "../config/load.ts";
import { runConnector, type RunSummary } from "../engine/runner.ts";
import { log } from "../log.ts";
import { loadActiveConnector } from "../store/connectors.ts";
import { createPgRunStore } from "../store/runs.ts";
import type { RunJob } from "../scheduler/queue.ts";

export function createWorker(opts: { pool: pg.Pool; secrets: SecretSource; env?: Record<string, string | undefined> }) {
  const connectors = new Map<string, ResolvedConnector>();
  const broker = createLocalBroker({ getConnector: (id) => connectors.get(id), secrets: opts.secrets });
  const store = createPgRunStore(opts.pool);

  async function handle(job: RunJob): Promise<RunSummary[]> {
    const conn = await loadActiveConnector(opts.pool, job.connectorId, opts.env);
    if (connectors.get(conn.metadata.id)?.configHash !== conn.configHash) broker.forget(conn.metadata.id); // config changed: new token
    connectors.set(conn.metadata.id, conn);
    try {
      const results = await runConnector({ connector: conn, broker, store, trigger: job.trigger });
      for (const r of results)
        log.info({ connector: conn.metadata.id, stream: r.stream, status: r.status, ok: r.recordsOk, trigger: job.trigger }, "job done");
      return results;
    } catch (e) {
      // e.g. connector disabled between enqueue and claim: not a crash, just nothing to do.
      log.warn({ connector: job.connectorId, err: (e as Error).message }, "job skipped");
      return [];
    }
  }

  return { handle, broker };
}
