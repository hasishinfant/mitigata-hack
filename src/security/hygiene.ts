// Credential hygiene, run by the scheduler:
//  - auto-disable connectors with credentials that haven't been used successfully for idle_disable_days
//    (an idle credential is pure risk: it can be stolen and nobody would notice it stopped being needed);
//  - alert (once a day) when a credential is older than max_age_days.
import type pg from "pg";
import { loadActiveConnector } from "../store/connectors.ts";
import { raiseAlertOnce } from "./alerts.ts";
import { credentialRefs } from "./posture.ts";

const DAY = 86_400_000;
export type HygieneReport = { disabled: string[]; rotate: string[] };

export async function runHygiene(pool: pg.Pool, opts: { now?: number; env?: Record<string, string | undefined> } = {}): Promise<HygieneReport> {
  const now = opts.now ?? Date.now();
  const report: HygieneReport = { disabled: [], rotate: [] };
  const rows = (
    await pool.query(
      `select k.id, k.last_success_at, k.enabled_at, v.validated_at
       from connectors k join connector_versions v on v.connector_id = k.id and v.version = k.active_version
       where k.status in ('enabled', 'paused')`,
    )
  ).rows;
  for (const row of rows) {
    let conn;
    try {
      conn = await loadActiveConnector(pool, row.id, opts.env);
    } catch {
      continue;
    }
    if (conn.connection.auth.type === "none") continue;
    const refs = credentialRefs(conn);
    const creds = (await pool.query("select ref, created_at from credential_meta where tenant_id = $1 and ref = any($2)", [conn.metadata.tenant, refs])).rows;

    const idleDays = conn.credential?.idle_disable_days;
    if (idleDays) {
      // Activity = last successful run, last config change, last re-enable, or last secret rotation.
      const times = [row.last_success_at, row.validated_at, row.enabled_at, ...creds.map((c) => c.created_at)].filter(Boolean).map((t) => Date.parse(t));
      const last = Math.max(...times);
      const idle = Math.floor((now - last) / DAY);
      if (idle >= idleDays) {
        const reason = `idle for ${idle} days (idle_disable_days: ${idleDays}); credential disabled to shrink blast radius`;
        await pool.query("update connectors set status = 'disabled', disabled_reason = $2, disabled_at = now(), next_run_at = null where id = $1", [row.id, reason]);
        await raiseAlertOnce(pool, row.id, "idle_disabled", reason, 0);
        report.disabled.push(row.id);
        continue;
      }
    }
    const maxAge = conn.credential?.max_age_days;
    if (maxAge)
      for (const c of creds) {
        const age = Math.floor((now - Date.parse(c.created_at)) / DAY);
        if (age > maxAge) {
          await raiseAlertOnce(pool, row.id, "credential_age", `rotate ${c.ref}: ${age} days old (max_age_days ${maxAge})`);
          report.rotate.push(`${row.id}:${c.ref}`);
        }
      }
  }
  return report;
}
