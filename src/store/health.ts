// Health per connection (FR-10): status, last run, records pulled, last error, plus schedule,
// quarantine, credential age and a recent-runs strip for the dashboard.
import type pg from "pg";
import { getPosture } from "../security/posture.ts";
import { loadActiveConnector } from "./connectors.ts";
import { integritySummary } from "./staging.ts";

export type Health = "healthy" | "warning" | "degraded" | "failing" | "stale" | "running" | "paused" | "disabled" | "never_run" | "config_error";

type RunRow = {
  stream: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  requests: number;
  records_ok: number;
  records_quarantined: number;
  retries: number;
  rate_limited_ms: number;
  trigger: string;
  last_error: string | null;
};

const RANK: Record<string, number> = { failed: 5, auth_failed: 5, degraded: 4, partial: 3, success: 1 };

/** Pure: derive one health word from connector state and its latest run per stream. */
export function deriveHealth(input: {
  status: string;
  configOk: boolean;
  latest: { status: string }[];
  lastSuccessAt: string | null;
  everyMs?: number;
  now: number;
}): Health {
  if (input.status === "disabled") return "disabled";
  if (input.status === "paused") return "paused";
  if (!input.configOk) return "config_error";
  if (input.latest.length === 0) return "never_run";
  if (input.latest.some((r) => r.status === "running")) return "running";
  const worst = input.latest.reduce((a, r) => ((RANK[r.status] ?? 0) > (RANK[a] ?? 0) ? r.status : a), "success");
  const base: Health = worst === "failed" || worst === "auth_failed" ? "failing" : worst === "degraded" ? "degraded" : worst === "partial" ? "warning" : "healthy";
  // Scheduled but no success for 3 intervals: data is going stale even if the last run "looked" fine.
  if ((base === "healthy" || base === "warning") && input.everyMs) {
    const last = input.lastSuccessAt ? Date.parse(input.lastSuccessAt) : 0;
    if (input.now - last > 3 * input.everyMs) return "stale";
  }
  return base;
}

export async function getHealth(pool: pg.Pool, env: Record<string, string | undefined> = process.env) {
  const now = Date.now();
  const connectors = (
    await pool.query("select id, source, tenant_id, status, disabled_reason, paused_until, next_run_at, last_success_at, active_version from connectors order by id")
  ).rows;
  const stored = new Map<string, number>();
  for (const t of ["users", "devices", "events"])
    for (const r of (await pool.query(`select connector_id, count(*)::int as n from ${t} group by 1`)).rows)
      stored.set(r.connector_id, (stored.get(r.connector_id) ?? 0) + r.n);
  const quarantine = new Map<string, number>(
    (await pool.query("select connector_id, count(*)::int as n from quarantine group by 1")).rows.map((r) => [r.connector_id, r.n]),
  );

  const integrity = await integritySummary(pool);
  const items = [];
  for (const c of connectors) {
    let cfg: Awaited<ReturnType<typeof loadActiveConnector>> | undefined;
    let configError: string | undefined;
    try {
      cfg = await loadActiveConnector(pool, c.id, env);
    } catch (e) {
      configError = (e as Error).message;
    }
    const latest = (
      await pool.query(
        `select distinct on (stream) stream, status, started_at, finished_at, requests, records_ok, records_quarantined,
                retries, rate_limited_ms, trigger, last_error
         from runs where connector_id = $1 order by stream, started_at desc`,
        [c.id],
      )
    ).rows as RunRow[];
    const recent = (
      await pool.query("select status, started_at from runs where connector_id = $1 order by started_at desc limit 12", [c.id])
    ).rows.map((r) => r.status as string);
    const last = latest.slice().sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at))[0];
    let posture: { risk: string; flags: { level: string; message: string }[] } | null = null;
    if (cfg) {
      try {
        const p = await getPosture(pool, c.id, env);
        posture = { risk: p.risk, flags: p.flags.slice(0, 5) };
      } catch {
        posture = null;
      }
    }
    const health = deriveHealth({
      status: c.status, configOk: !configError, latest, lastSuccessAt: c.last_success_at, everyMs: cfg?.runtime.schedule?.everyMs, now,
    });
    items.push({
      id: c.id,
      source: c.source,
      tenant: c.tenant_id,
      health,
      status: c.status,
      reason: c.disabled_reason ?? configError ?? null,
      paused_until: c.paused_until,
      auth_type: cfg?.connection.auth.type ?? null,
      entities: cfg ? [...new Set(cfg.streams.map((s) => s.entity))] : [],
      streams: latest.map((r) => ({ name: r.stream, status: r.status, records_ok: r.records_ok, last_error: r.last_error, started_at: r.started_at })),
      schedule_every: cfg?.schedule?.every ?? null,
      next_run_at: c.next_run_at,
      last_run: last
        ? {
            stream: last.stream, status: last.status, trigger: last.trigger, started_at: last.started_at, finished_at: last.finished_at,
            requests: last.requests, records_pulled: last.records_ok, records_quarantined: last.records_quarantined,
            retries: last.retries, rate_limited_ms: last.rate_limited_ms,
          }
        : null,
      last_error: latest.find((r) => r.last_error && r.status !== "success")?.last_error ?? null,
      last_success_at: c.last_success_at,
      records_in_store: stored.get(c.id) ?? 0,
      quarantine_total: quarantine.get(c.id) ?? 0,
      recent_runs: recent,
      config_version: c.active_version,
      posture,
      // Latest Sync Integrity Receipt decision per stream, and syncs held for review (T7/T8).
      integrity: integrity.get(c.id) ?? { streams: [], held: 0 },
    });
  }
  const summary: Record<string, number> = { total: items.length };
  for (const i of items) summary[i.health] = (summary[i.health] ?? 0) + 1;
  return { generated_at: new Date(now).toISOString(), summary, connectors: items };
}
