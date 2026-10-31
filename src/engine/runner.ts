// Runs a connector: for each stream, page through the provider via the broker, map records,
// and commit each page (upserts + quarantine + counters + checkpoint) atomically.
// Failed runs resume from the checkpoint; repeated failures open a circuit breaker;
// a sudden drop in field hit rate marks the run degraded (schema drift).
// Provider-agnostic: everything provider-specific comes from the config.
import { randomUUID } from "node:crypto";
import type { ResolvedConnector } from "../config/load.ts";
import type { Entity, StreamConfig } from "../config/schema.ts";
import { log } from "../log.ts";
import { mapRecord, type MappedRecord } from "../mapping/mapper.ts";
import { resolvePath } from "../mapping/paths.ts";
import { redactValue } from "../mapping/scanner.ts";
import { toIso } from "../mapping/transforms.ts";
import { BrokerError, type Broker } from "../broker/types.ts";
import { createPaginator, type PageRequest } from "./paginate/index.ts";

export type RunTrigger = "manual" | "schedule" | "api";
export type RunStatus = "running" | "success" | "partial" | "failed" | "auth_failed" | "degraded" | "paused";
export type FieldStats = { records: number; hits: Record<string, number> };
export type Checkpoint = { nextUrl?: string; nextBody?: Record<string, unknown>; configHash: string; cursorValue?: string };

export type QuarantineItem = { raw: unknown; errors: string[] };
export type PageCommit = {
  runId: string;
  connectorId: string;
  stream: string;
  tenant: string;
  source: string;
  entity: Entity;
  fetchedAt: Date;
  records: MappedRecord[];
  quarantined: QuarantineItem[];
  requests: number;
  checkpoint: Checkpoint | null; // null = stream complete, clear the checkpoint
};
export type FinishRun = {
  runId: string;
  connectorId: string;
  status: RunStatus;
  requests: number;
  retries: number;
  rateLimitedMs: number;
  fieldStats: FieldStats;
  lastError?: string;
};

export interface RunStore {
  startRun(r: { runId: string; connectorId: string; stream: string; configHash: string; startedAt: Date; resumed: boolean; trigger: RunTrigger }): Promise<void>;
  commitPage(p: PageCommit): Promise<void>;
  finishRun(r: FinishRun): Promise<void>;
  loadCheckpoint(connectorId: string, stream: string): Promise<Checkpoint | null>;
  /** Incremental sync: highest cursor_field value seen in a fully completed run. */
  saveWatermark(connectorId: string, stream: string, value: string): Promise<void>;
  previousFieldStats(connectorId: string, stream: string, excludeRunId: string): Promise<FieldStats | null>;
  connectorState(connectorId: string): Promise<{ status: string; pausedUntil: Date | null; reason: string | null }>;
  recentStatuses(connectorId: string, n: number): Promise<RunStatus[]>;
  pause(connectorId: string, until: Date, reason: string): Promise<void>;
  resume(connectorId: string): Promise<void>;
  raiseAlert(connectorId: string, kind: string, message: string): Promise<void>;
}

export type RunSummary = {
  runId: string;
  stream: string;
  status: RunStatus;
  requests: number;
  recordsOk: number;
  recordsQuarantined: number;
  retries: number;
  rateLimitedMs: number;
  resumed: boolean;
  incrementalFrom?: string; // watermark injected for this run
  watermark?: string; // new watermark saved after this run
  lastError?: string;
};

export class RunFailure extends Error {
  status: RunStatus;
  constructor(status: RunStatus, message: string) {
    super(message);
    this.status = status;
  }
}

const FAILURE: RunStatus[] = ["failed", "auth_failed"];
const DRIFT_MIN_RECORDS = 5;
const DRIFT_JUMP = 0.5;
const RAW_LIMIT = 16 * 1024;

/** "-7d" / "-12h" / "-30m" relative to now, or an absolute date, as ISO 8601 UTC. */
export function initialCursor(initial: string | undefined, nowMs: number): string | undefined {
  if (!initial) return undefined;
  const m = /^-(\d+)([mhd])$/.exec(initial);
  if (m) return new Date(nowMs - Number(m[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "m" | "h" | "d"]).toISOString();
  return toIso(initial);
}

function cursorOf(raw: unknown, field: string): string | undefined {
  const v = resolvePath(raw, field);
  if (v === undefined || v === null || v === "") return undefined;
  try {
    return toIso(v);
  } catch {
    return undefined;
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

function classifyHttp(status: number, body: string, retries: number): RunFailure {
  const snippet = body.slice(0, 200).replace(/\s+/g, " ");
  if (status === 401 || status === 403) return new RunFailure("auth_failed", `HTTP ${status}: credentials rejected`);
  const after = retries ? ` after ${retries} retries` : "";
  return new RunFailure("failed", `HTTP ${status}${after}${snippet ? `: ${snippet}` : ""}`);
}

/** Fields whose miss rate jumped by >= 50 points versus the previous good run. */
export function detectDrift(prev: FieldStats | null, cur: FieldStats, fields: string[]): string[] {
  if (!prev || prev.records < DRIFT_MIN_RECORDS || cur.records < DRIFT_MIN_RECORDS) return [];
  const out: string[] = [];
  for (const f of fields) {
    const prevMiss = 1 - (prev.hits[f] ?? 0) / prev.records;
    const curMiss = 1 - (cur.hits[f] ?? 0) / cur.records;
    if (curMiss > 0.5 && curMiss - prevMiss >= DRIFT_JUMP)
      out.push(`${f} missing in ${Math.round(curMiss * 100)}% of records (was ${Math.round(prevMiss * 100)}%)`);
  }
  return out;
}

function driftFields(stream: StreamConfig): string[] {
  return Object.entries(stream.mapping)
    .filter(([f, spec]) => f !== "attributes" && spec.const === undefined)
    .map(([f]) => f);
}

export async function runStream(opts: {
  connector: ResolvedConnector;
  stream: StreamConfig;
  broker: Broker;
  store: RunStore;
  trigger?: RunTrigger;
}): Promise<RunSummary> {
  const { connector: conn, stream, broker, store } = opts;
  const connectorId = conn.metadata.id;
  const runId = randomUUID();
  const paginator = createPaginator(stream.pagination, stream.request.paging_in ?? "query");

  const cp = await store.loadCheckpoint(connectorId, stream.name);
  const resumed = Boolean(cp?.nextUrl) && cp!.configHash === conn.configHash;
  const inc = stream.incremental;
  const runStart = new Date();
  let incrementalFrom: string | undefined;
  let req: PageRequest | null;
  if (resumed) {
    req = { url: new URL(cp!.nextUrl!), ...(cp!.nextBody ? { body: cp!.nextBody } : {}) };
  } else {
    const base = buildBaseUrl(conn, stream);
    // Incremental: only fetch what changed since the last fully completed run (or since `initial`).
    if (inc) {
      incrementalFrom = cp?.cursorValue ?? initialCursor(inc.initial, runStart.getTime());
      if (incrementalFrom) {
        const fill = (t: string) => t.replaceAll("{{cursor}}", incrementalFrom!).replaceAll("{{now}}", runStart.toISOString());
        base.searchParams.set(inc.param, fill(inc.template));
        for (const [k, v] of Object.entries(inc.extra_params ?? {})) base.searchParams.set(k, fill(v));
      }
    }
    req = paginator.start({ url: base, ...(stream.request.body ? { body: structuredClone(stream.request.body) } : {}) });
  }
  let maxCursor: string | undefined;
  let completed = false;

  const summary: RunSummary = {
    runId, stream: stream.name, status: "running", requests: 0, recordsOk: 0, recordsQuarantined: 0, retries: 0, rateLimitedMs: 0, resumed,
    ...(incrementalFrom ? { incrementalFrom } : {}),
  };
  const stats: FieldStats = { records: 0, hits: {} };
  const ctx = { connector: connectorId, stream: stream.name, run: runId };
  await store.startRun({ runId, connectorId, stream: stream.name, configHash: conn.configHash, startedAt: new Date(), resumed, trigger: opts.trigger ?? "manual" });
  if (resumed) log.info({ ...ctx, path: req?.url.pathname }, "resuming from checkpoint");

  let stopReason: string | undefined;
  try {
    while (req) {
      if (summary.requests >= conn.runtime.maxRequestsPerRun) {
        stopReason = `stopped at policy.max_requests_per_run (${conn.runtime.maxRequestsPerRun}); next run continues from checkpoint`;
        break;
      }
      summary.requests++;
      let res;
      try {
        res = await broker.request({ connectorId, method: stream.request.method, url: req.url.href, body: req.body, headers: stream.request.headers });
      } catch (e) {
        if (e instanceof BrokerError) {
          summary.retries += e.retries;
          summary.rateLimitedMs += e.rateLimitedMs;
        }
        throw e;
      }
      summary.retries += res.retries;
      summary.rateLimitedMs += res.rateLimitedMs;
      if (res.status < 200 || res.status >= 300) throw classifyHttp(res.status, res.body, res.retries);

      let body: unknown;
      try {
        body = res.body.trim() === "" ? null : JSON.parse(res.body);
      } catch {
        throw new RunFailure("failed", "response is not valid JSON");
      }
      const raws = extractRecords(body, stream.records_path);
      const records: MappedRecord[] = [];
      const quarantined: QuarantineItem[] = [];
      for (const raw of raws) {
        const r = mapRecord(raw, stream.entity, stream.mapping);
        stats.records++;
        for (const f of r.present) stats.hits[f] = (stats.hits[f] ?? 0) + 1;
        if (inc) {
          const c = cursorOf(raw, inc.cursor_field);
          if (c && (!maxCursor || Date.parse(c) > Date.parse(maxCursor))) maxCursor = c;
        }
        if (r.ok) {
          // Data minimisation: raw payloads are kept only if the config opts in, and always secret-redacted.
          if (conn.data?.store_raw) {
            const red = redactValue(raw);
            const text = JSON.stringify(red) ?? "";
            r.record.attributes._raw = text.length > RAW_LIMIT ? { truncated: true, preview: text.slice(0, RAW_LIMIT) } : red;
          }
          records.push(r.record);
        } else quarantined.push({ raw, errors: r.errors });
      }
      const next = paginator.next({ req, headers: res.headers, body, records: raws.length });
      await store.commitPage({
        runId, connectorId, stream: stream.name, tenant: conn.metadata.tenant, source: conn.metadata.source,
        entity: stream.entity, fetchedAt: new Date(), records, quarantined, requests: 1,
        checkpoint: next ? { nextUrl: next.url.href, ...(next.body ? { nextBody: next.body } : {}), configHash: conn.configHash } : null,
      });
      summary.recordsOk += records.length;
      summary.recordsQuarantined += quarantined.length;
      log.debug({ ...ctx, page: summary.requests, ok: records.length, quarantined: quarantined.length }, "page committed");

      if (summary.recordsOk + summary.recordsQuarantined >= conn.runtime.maxRecordsPerRun && next) {
        stopReason = `stopped at policy.max_records_per_run (${conn.runtime.maxRecordsPerRun}); next run continues from checkpoint`;
        break;
      }
      req = next;
    }
    completed = req === null && !stopReason;
    summary.status = summary.recordsQuarantined > 0 || stopReason ? "partial" : "success";
    if (stopReason) summary.lastError = stopReason;
    else if (summary.recordsQuarantined > 0) summary.lastError = `${summary.recordsQuarantined} record(s) quarantined`;

    const drift = detectDrift(await store.previousFieldStats(connectorId, stream.name, runId), stats, driftFields(stream));
    if (drift.length) {
      summary.status = "degraded";
      summary.lastError = `schema drift: ${drift.join("; ")}`;
    }
  } catch (e) {
    if (e instanceof RunFailure) {
      summary.status = e.status;
      summary.lastError = e.message;
    } else if (e instanceof BrokerError) {
      summary.status = e.kind === "secret_missing" || e.kind === "auth_failed" ? "auth_failed" : "failed";
      summary.lastError = `${e.kind}: ${e.message}`;
    } else {
      summary.status = "failed";
      summary.lastError = `internal error: ${(e as Error).message}`;
      log.error({ ...ctx, err: (e as Error).message }, "run crashed");
    }
  }

  // Advance the watermark only after a run that saw every page: a partial run may have skipped newer records.
  if (inc && completed && maxCursor && !FAILURE.includes(summary.status) && (!cp?.cursorValue || Date.parse(maxCursor) > Date.parse(cp.cursorValue))) {
    await store.saveWatermark(connectorId, stream.name, maxCursor);
    summary.watermark = maxCursor;
  }

  await store.finishRun({
    runId, connectorId, status: summary.status, requests: summary.requests, retries: summary.retries,
    rateLimitedMs: summary.rateLimitedMs, fieldStats: stats, lastError: summary.lastError,
  });
  if (summary.status === "degraded" || summary.status === "auth_failed")
    await store.raiseAlert(connectorId, summary.status, `${stream.name}: ${summary.lastError}`);
  if (FAILURE.includes(summary.status)) {
    await maybeOpenBreaker(conn, store, summary);
    // Fire once per failure streak, when it reaches alerts.on_consecutive_failures.
    const n = conn.alerts?.on_consecutive_failures ?? 3;
    const recent = await store.recentStatuses(connectorId, n + 1);
    const streak = recent.findIndex((s) => !FAILURE.includes(s));
    if ((streak === -1 ? recent.length : streak) === n)
      await store.raiseAlert(connectorId, "consecutive_failures", `${n} consecutive failed runs; last: ${summary.lastError ?? summary.status}`);
  }

  log.info(
    { ...ctx, status: summary.status, requests: summary.requests, ok: summary.recordsOk, quarantined: summary.recordsQuarantined, retries: summary.retries },
    "run finished",
  );
  return summary;
}

async function maybeOpenBreaker(conn: ResolvedConnector, store: RunStore, summary: RunSummary): Promise<void> {
  const { failuresToOpen, coolDownMs } = conn.runtime.breaker;
  const recent = await store.recentStatuses(conn.metadata.id, failuresToOpen);
  if (recent.length < failuresToOpen || !recent.every((s) => FAILURE.includes(s))) return;
  const until = new Date(Date.now() + coolDownMs);
  const reason = `circuit open after ${failuresToOpen} consecutive failures (last: ${summary.lastError ?? summary.status})`;
  await store.pause(conn.metadata.id, until, reason);
  await store.raiseAlert(conn.metadata.id, "circuit_open", `${reason}; paused until ${until.toISOString()}`);
  log.warn({ connector: conn.metadata.id, until: until.toISOString() }, "circuit breaker opened");
}

export async function runConnector(opts: {
  connector: ResolvedConnector;
  broker: Broker;
  store: RunStore;
  streams?: string[];
  trigger?: RunTrigger;
}): Promise<RunSummary[]> {
  const { connector: conn, store } = opts;
  const state = await store.connectorState(conn.metadata.id);
  const streams = conn.streams.filter((s) => !opts.streams || opts.streams.includes(s.name));
  if (state.status === "disabled") throw new Error(`connector ${conn.metadata.id} is disabled${state.reason ? `: ${state.reason}` : ""}`);
  if (state.status === "paused") {
    if (state.pausedUntil && state.pausedUntil.getTime() > Date.now()) {
      const msg = `circuit open until ${state.pausedUntil.toISOString()}${state.reason ? ` (${state.reason})` : ""}`;
      return streams.map((s) => ({
        runId: "", stream: s.name, status: "paused" as const, requests: 0, recordsOk: 0, recordsQuarantined: 0, retries: 0, rateLimitedMs: 0, resumed: false, lastError: msg,
      }));
    }
    await store.resume(conn.metadata.id); // cool-down over: half-open, try again
  }
  const out: RunSummary[] = [];
  for (const stream of streams) out.push(await runStream({ ...opts, stream }));
  return out;
}
