// Worker: claims queued runs and executes them through the broker. Configs are reloaded for every
// job, so `ix update` takes effect on the next run. In production the broker is the separate broker
// process (socket client) and this process holds no secrets. Tests may pass local secrets instead.
import type pg from "pg";
import { createLocalBroker } from "../broker/client.ts";
import type { Broker, SecretSource } from "../broker/types.ts";
import type { ResolvedConnector } from "../config/load.ts";
import { runConnector, type RunSummary } from "../engine/runner.ts";
import { log } from "../log.ts";
import { loadActiveConnector } from "../store/connectors.ts";
import { createPgRunStore } from "../store/runs.ts";
import type { RunJob } from "../scheduler/queue.ts";

type ForgettingBroker = Broker & { forget(connectorId?: string): void | Promise<void> };

export function createWorker(opts: { pool: pg.Pool; broker?: ForgettingBroker; secrets?: SecretSource; env?: Record<string, string | undefined> }) {
  const configs = new Map<string, ResolvedConnector>();
  const broker: ForgettingBroker =
    opts.broker ?? createLocalBroker({ getConnector: (id) => configs.get(id), secrets: opts.secrets ?? { get: async () => undefined } });
  const store = createPgRunStore(opts.pool);

  async function handle(job: RunJob): Promise<RunSummary[]> {
    try {
      const conn = await loadActiveConnector(opts.pool, job.connectorId, opts.env);
      if (configs.has(conn.metadata.id) && configs.get(conn.metadata.id)?.configHash !== conn.configHash) await broker.forget(conn.metadata.id);
      configs.set(conn.metadata.id, conn);
      const results = await runConnector({ connector: conn, broker, store, trigger: job.trigger });
      for (const r of results)
        log.info({ connector: conn.metadata.id, stream: r.stream, status: r.status, ok: r.recordsOk, trigger: job.trigger }, "job done");
      return results;
    } catch (e) {
      // e.g. connector disabled or removed between enqueue and claim: nothing to do, not a crash.
      log.warn({ connector: job.connectorId, err: (e as Error).message }, "job skipped");
      return [];
    }
  }

  return { handle, broker };
}
