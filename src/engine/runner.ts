// Runs a connector: for each stream, page through the provider via the broker, map records,
// commit each page (upserts + quarantine + counters) atomically, and record the run outcome.
// Provider-agnostic: everything provider-specific comes from the config.
import { randomUUID } from "node:crypto";
import type { ResolvedConnector } from "../config/load.ts";
import type { Entity, StreamConfig } from "../config/schema.ts";
import { log } from "../log.ts";
import { mapRecord, type MappedRecord } from "../mapping/mapper.ts";
import { resolvePath } from "../mapping/paths.ts";
import { BrokerError, type Broker } from "../broker/types.ts";
import { createPaginator } from "./paginate/index.ts";

export type RunStatus = "running" | "success" | "partial" | "failed" | "auth_failed" | "degraded" | "paused";

export type QuarantineItem = { raw: unknown; errors: string[] };
export type PageCommit = {
  runId: string;
  connectorId: string;
  tenant: string;
  source: string;
  entity: Entity;
  fetchedAt: Date;
  records: MappedRecord[];
  quarantined: QuarantineItem[];
  requests: number;
};

export interface RunStore {
  startRun(r: { runId: string; connectorId: string; stream: string; configHash: string; startedAt: Date }): Promise<void>;
  commitPage(p: PageCommit): Promise<void>;
  finishRun(r: { runId: string; connectorId: string; status: RunStatus; requests: number; lastError?: string }): Promise<void>;
}

export type RunSummary = {
  runId: string;
  stream: string;
  status: RunStatus;
  requests: number;
  recordsOk: number;
  recordsQuarantined: number;
  lastError?: string;
};

export class RunFailure extends Error {
  status: RunStatus;
  constructor(status: RunStatus, message: string) {
    super(message);
    this.status = status;
  }
}

export function buildBaseUrl(conn: ResolvedConnector, stream: StreamConfig): URL {
  const url = new URL(conn.connection.base_url.replace(/\/$/, "") + stream.request.path);
  for (const [k, v] of Object.entries(stream.request.params ?? {})) url.searchParams.set(k, String(v));
  return url;
}

export function extractRecords(body: unknown, recordsPath: string | undefined): unknown[] {
  const v = resolvePath(body, recordsPath ?? "$");
  if (Array.isArray(v)) return v;
  if (v === undefined || v === null) return [];
  throw new RunFailure("failed", `records_path "${recordsPath ?? "$"}" resolved to ${typeof v}, expected an array`);
}

function classifyHttp(status: number, body: string): RunFailure {
  const snippet = body.slice(0, 200).replace(/\s+/g, " ");
  if (status === 401 || status === 403) return new RunFailure("auth_failed", `HTTP ${status}: credentials rejected`);
  return new RunFailure("failed", `HTTP ${status}${snippet ? `: ${snippet}` : ""}`);
}

export async function runStream(opts: {
  connector: ResolvedConnector;
  stream: StreamConfig;
  broker: Broker;
  store: RunStore;
}): Promise<RunSummary> {
  const { connector: conn, stream, broker, store } = opts;
  const runId = randomUUID();
  const summary: RunSummary = { runId, stream: stream.name, status: "running", requests: 0, recordsOk: 0, recordsQuarantined: 0 };
  const ctx = { connector: conn.metadata.id, stream: stream.name, run: runId };
  await store.startRun({ runId, connectorId: conn.metadata.id, stream: stream.name, configHash: conn.configHash, startedAt: new Date() });

  const paginator = createPaginator(stream.pagination);
  let url: URL | null = paginator.start(buildBaseUrl(conn, stream));
  let stopReason: string | undefined;
  try {
    while (url) {
      if (summary.requests >= conn.runtime.maxRequestsPerRun) {
        stopReason = `stopped at policy.max_requests_per_run (${conn.runtime.maxRequestsPerRun})`;
        break;
      }
      summary.requests++;
      const res = await broker.request({ connectorId: conn.metadata.id, method: "GET", url: url.href, headers: stream.request.headers });
      if (res.status < 200 || res.status >= 300) throw classifyHttp(res.status, res.body);

      let body: unknown;
      try {
        body = res.body.trim() === "" ? null : JSON.parse(res.body);
      } catch {
        throw new RunFailure("failed", "response is not valid JSON");
      }
      const raws = extractRecords(body, stream.records_path);
      const fetchedAt = new Date();
      const records: MappedRecord[] = [];
      const quarantined: QuarantineItem[] = [];
      for (const raw of raws) {
        const r = mapRecord(raw, stream.entity, stream.mapping);
        if (r.ok) records.push(r.record);
        else quarantined.push({ raw, errors: r.errors });
      }
      await store.commitPage({
        runId, connectorId: conn.metadata.id, tenant: conn.metadata.tenant, source: conn.metadata.source,
        entity: stream.entity, fetchedAt, records, quarantined, requests: 1,
      });
      summary.recordsOk += records.length;
      summary.recordsQuarantined += quarantined.length;
      log.debug({ ...ctx, page: summary.requests, ok: records.length, quarantined: quarantined.length }, "page committed");

      if (summary.recordsOk + summary.recordsQuarantined >= conn.runtime.maxRecordsPerRun) {
        stopReason = `stopped at policy.max_records_per_run (${conn.runtime.maxRecordsPerRun})`;
        break;
      }
      url = paginator.next({ url, headers: res.headers, body, records: raws.length });
    }
    summary.status = summary.recordsQuarantined > 0 || stopReason ? "partial" : "success";
    if (stopReason) summary.lastError = stopReason;
    else if (summary.recordsQuarantined > 0) summary.lastError = `${summary.recordsQuarantined} record(s) quarantined`;
  } catch (e) {
    if (e instanceof RunFailure) {
      summary.status = e.status;
      summary.lastError = e.message;
    } else if (e instanceof BrokerError) {
      summary.status = e.kind === "secret_missing" ? "auth_failed" : "failed";
      summary.lastError = `${e.kind}: ${e.message}`;
    } else {
      summary.status = "failed";
      summary.lastError = `internal error: ${(e as Error).message}`;
      log.error({ ...ctx, err: (e as Error).message }, "run crashed");
    }
  }
  await store.finishRun({ runId, connectorId: conn.metadata.id, status: summary.status, requests: summary.requests, lastError: summary.lastError });
  log.info({ ...ctx, status: summary.status, requests: summary.requests, ok: summary.recordsOk, quarantined: summary.recordsQuarantined }, "run finished");
  return summary;
}

export async function runConnector(opts: {
  connector: ResolvedConnector;
  broker: Broker;
  store: RunStore;
  streams?: string[];
}): Promise<RunSummary[]> {
  const out: RunSummary[] = [];
  for (const stream of opts.connector.streams) {
    if (opts.streams && !opts.streams.includes(stream.name)) continue;
    out.push(await runStream({ ...opts, stream }));
  }
  return out;
}
