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

export type DeliveryReport = { sent: number; noChannel: number; failed: number; alreadyDelivered: number };

/**
 * Deliver pending alerts through the broker. The broker reads each row itself, sends it and marks it delivered;
 * this side only picks the ids. Failed or throttled deliveries stay pending and are retried next call.
 * At least once: a crash between the webhook accepting a message and the commit resends it.
 */
export async function deliverAlerts(pool: pg.Pool, admin: BrokerAdmin, limit = 20): Promise<DeliveryReport> {
  const rows = (
    await pool.query(
      `select id, connector_id, kind, message from alerts
       where delivered = false order by id limit $1`,
      [limit],
    )
  ).rows as { id: number; connector_id: string | null; kind: string; message: string }[];
  const report: DeliveryReport = { sent: 0, noChannel: 0, failed: 0, alreadyDelivered: 0 };
  for (const a of rows) {
    if (!a.connector_id) {
      await pool.query("update alerts set delivered = true, channel = 'none', delivered_at = now() where id = $1", [a.id]);
      report.noChannel++;
      continue;
    }
    try {
      const r = await admin.notify(a.id);
      if (r.delivered) report.sent++;
      else if (r.channel === "none") report.noChannel++;
      else report.failed++;
    } catch (e) {
      // The broker may have delivered and committed the alert even though we got an error (e.g. its response was
      // lost). Only a still-pending row is marked as an error: a delivered row keeps channel 'slack' and stays in the
      // throttle's count. "Already delivered" means it is done, not that this delivery failed.
      if ((e as { statusCode?: number }).statusCode === 409) {
        report.alreadyDelivered++;
        continue;
      }
      await pool.query("update alerts set channel = 'error' where id = $1 and delivered = false", [a.id]);
      report.failed++;
    }
  }
  return report;
}
