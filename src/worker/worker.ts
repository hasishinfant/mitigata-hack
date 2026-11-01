// Worker: claims queued runs and executes them through the broker. Configs are reloaded for every
// job, so `ix update` takes effect on the next run. In production the broker is the separate broker
// process (socket client) and this process holds no secrets. Tests may pass local secrets instead.
import type pg from "pg";
import { createLocalBroker } from "../broker/client.ts";
import type { Broker, SecretSource } from "../broker/types.ts";
import type { ResolvedConnector } from "../config/load.ts";
import { ConnectorBusy, runConnector, type RunSummary } from "../engine/runner.ts";
import { log } from "../log.ts";
import { loadActiveConnector } from "../store/connectors.ts";
import { createPgRunStore } from "../store/runs.ts";
import type { RunJob } from "../scheduler/queue.ts";

// The broker process notices a new config version itself and drops that connector's token; workers have
// no way to flush its caches. Only the in-process broker (tests, no broker process) is flushed from here.
export function createWorker(opts: { pool: pg.Pool; broker?: Broker; secrets?: SecretSource; env?: Record<string, string | undefined> }) {
  const configs = new Map<string, ResolvedConnector>();
  const local = opts.broker ? undefined : createLocalBroker({ getConnector: (id) => configs.get(id), secrets: opts.secrets ?? { get: async () => undefined } });
  const broker: Broker = opts.broker ?? local!;
  const store = createPgRunStore(opts.pool);

  async function handle(job: RunJob): Promise<RunSummary[]> {
    try {
      const conn = await loadActiveConnector(opts.pool, job.connectorId, opts.env);
      if (local && configs.has(conn.metadata.id) && configs.get(conn.metadata.id)?.configHash !== conn.configHash) local.forget(conn.metadata.id);
      configs.set(conn.metadata.id, conn);
      const results = await runConnector({ connector: conn, broker, store, trigger: job.trigger });
      for (const r of results)
        log.info({ connector: conn.metadata.id, stream: r.stream, status: r.status, ok: r.recordsOk, trigger: job.trigger }, "job done");
      return results;
    } catch (e) {
      // Another run holds the connector's lock (e.g. an `ix run`): that run does the work; skip this job.
      if (e instanceof ConnectorBusy) {
        log.info({ connector: job.connectorId }, "job skipped: connector already running");
        return [];
      }
      // e.g. connector disabled or removed between enqueue and claim: nothing to do, not a crash.
      log.warn({ connector: job.connectorId, err: (e as Error).message }, "job skipped");
      return [];
    }
  }

  return { handle, broker };
}
