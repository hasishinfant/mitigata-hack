// Incident mode: while an incident is active, connectors with schedule.incident_every poll faster (audit logs, mostly),
// so an attacker's next move shows up in minutes, not at the next normal interval.
// An incident starts with a security alert (a canary fired, our credential used from a foreign IP) or an explicit
// `ix incident start`; it ends with `ix incident stop` or when the window passes with no new security alert.
// State lives in the alerts table (no extra schema): the latest security alert vs the latest incident_closed.
import type pg from "pg";

export const SECURITY_ALERT_KINDS = ["canary_triggered", "foreign_ip_use", "incident_declared"] as const;
export const DEFAULT_INCIDENT_WINDOW_MS = 2 * 3_600_000;

export type IncidentState = { active: boolean; since: string | null; until: string | null; reason: string | null; trigger_alert_id: number | null };

export async function incidentState(pool: pg.Pool, now = Date.now(), windowMs = windowFromEnv()): Promise<IncidentState> {
  const r = (
    await pool.query(
      `with closed as (select coalesce(max(id), 0) as id from alerts where kind = 'incident_closed')
       select a.id, a.kind, a.message, a.created_at,
              (select min(created_at) from alerts b, closed where b.kind = any($1) and b.id > closed.id and b.created_at > $2) as first_at
       from alerts a, closed where a.kind = any($1) and a.id > closed.id and a.created_at > $2 order by a.id desc limit 1`,
      [SECURITY_ALERT_KINDS, new Date(now - windowMs)],
    )
  ).rows[0] as { id: number; kind: string; message: string; created_at: string; first_at: string } | undefined;
  if (!r) return { active: false, since: null, until: null, reason: null, trigger_alert_id: null };
  return {
    active: true, since: r.first_at, until: new Date(Date.parse(r.created_at) + windowMs).toISOString(),
    reason: `${r.kind}: ${r.message}`.slice(0, 300), trigger_alert_id: Number(r.id),
  };
}

export function windowFromEnv(env: Record<string, string | undefined> = process.env): number {
  const m = Number(env.IX_INCIDENT_WINDOW_MIN);
  return Number.isFinite(m) && m > 0 ? m * 60_000 : DEFAULT_INCIDENT_WINDOW_MS;
}

export async function declareIncident(pool: pg.Pool, reason: string, actor: string): Promise<void> {
  await pool.query("insert into alerts (connector_id, kind, message) values (null, 'incident_declared', $1)", [`${reason} (declared by ${actor})`.slice(0, 1000)]);
}
export async function closeIncident(pool: pg.Pool, actor: string): Promise<void> {
  await pool.query("insert into alerts (connector_id, kind, message, delivered, channel) values (null, 'incident_closed', $1, true, 'none')", [`incident closed by ${actor}`]);
}
