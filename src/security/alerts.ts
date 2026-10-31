// Alerts: rows in `alerts`, delivered to Slack by the broker (the webhook URL is a secret).
import type pg from "pg";
import type { BrokerAdmin } from "../broker/remote.ts";

/** Insert an alert unless the same kind was raised for this connector within `withinHours`. */
export async function raiseAlertOnce(pool: pg.Pool, connectorId: string, kind: string, message: string, withinHours = 24): Promise<boolean> {
  const recent = await pool.query(
    "select 1 from alerts where connector_id = $1 and kind = $2 and created_at > now() - make_interval(hours => $3) limit 1",
    [connectorId, kind, withinHours],
  );
  if (recent.rowCount) return false;
  await pool.query("insert into alerts (connector_id, kind, message) values ($1, $2, $3)", [connectorId, kind, message]);
  return true;
}

export type DeliveryReport = { sent: number; noChannel: number; failed: number };

/** Deliver pending alerts through the broker. Failed deliveries are retried on the next call. */
export async function deliverAlerts(pool: pg.Pool, admin: BrokerAdmin, limit = 20): Promise<DeliveryReport> {
  const rows = (
    await pool.query(
      `select id, connector_id, kind, message from alerts
       where delivered = false order by id limit $1`,
      [limit],
    )
  ).rows as { id: number; connector_id: string | null; kind: string; message: string }[];
  const report: DeliveryReport = { sent: 0, noChannel: 0, failed: 0 };
  for (const a of rows) {
    if (!a.connector_id) {
      await pool.query("update alerts set delivered = true, channel = 'none', delivered_at = now() where id = $1", [a.id]);
      report.noChannel++;
      continue;
    }
    try {
      const r = await admin.notify(a.connector_id, `:rotating_light: [IntegrateX] ${a.connector_id} · ${a.kind}: ${a.message}`);
      const done = r.delivered || r.channel === "none";
      await pool.query("update alerts set delivered = $2, channel = $3, delivered_at = case when $2 then now() end where id = $1", [a.id, done, r.channel]);
      if (r.delivered) report.sent++;
      else if (r.channel === "none") report.noChannel++;
      else report.failed++;
    } catch {
      await pool.query("update alerts set channel = 'error' where id = $1", [a.id]);
      report.failed++;
    }
  }
  return report;
}
