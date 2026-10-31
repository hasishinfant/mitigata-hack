// Kill switch. In order:
//  1. disable every connector (app DB) so nothing is scheduled and the broker refuses their calls;
//  2. drop queued runs;
//  3. broker: revoke cached OAuth tokens where a revocation endpoint exists, wipe all in-memory tokens,
//     optionally delete every stored secret;
//  4. raise an alert and return a per-connector revocation checklist for the humans.
import type { PgBoss } from "pg-boss";
import type pg from "pg";
import type { BrokerAdmin } from "../broker/remote.ts";
import { RUN_QUEUE } from "../scheduler/queue.ts";
import { loadActiveConnector } from "../store/connectors.ts";
import { credentialRefs } from "./posture.ts";

export type ChecklistItem = {
  connector_id: string;
  source: string;
  auth_type: string;
  refs: string[];
  action: "revoked_by_api" | "revoke_manually" | "nothing_to_revoke";
  detail: string;
};
export type PanicReport = {
  at: string;
  disabled: string[];
  queued_runs_cancelled: number;
  queued_runs_error?: string;
  broker: { tokens_revoked: number; secrets_purged: number; error?: string };
  checklist: ChecklistItem[];
};

export async function panic(
  pool: pg.Pool,
  opts: { admin?: BrokerAdmin; boss?: PgBoss; purgeSecrets?: boolean; actor?: string; env?: Record<string, string | undefined> } = {},
): Promise<PanicReport> {
  const at = new Date().toISOString();
  const actor = opts.actor ?? "operator";
  const disabled = (
    await pool.query(
      "update connectors set status = 'disabled', disabled_reason = $1, disabled_at = now(), next_run_at = null where status <> 'disabled' returning id",
      [`panic by ${actor} at ${at}`],
    )
  ).rows.map((r) => r.id as string);

  let cancelled = 0;
  let queuedRunsError: string | undefined;
  if (opts.boss) {
    try {
      cancelled = await opts.boss.deleteQueuedJobs(RUN_QUEUE);
    } catch (e) {
      queuedRunsError = `queued run cancellation failed: ${(e as Error).message}`;
    }
  } else queuedRunsError = "job queue unavailable; queued runs could not be confirmed as cancelled";

  const broker: PanicReport["broker"] = { tokens_revoked: 0, secrets_purged: 0 };
  let revocations: { connectorId: string; revoked: boolean; detail: string }[] = [];
  if (opts.admin) {
    try {
      const r = await opts.admin.panic({ purgeSecrets: opts.purgeSecrets, actor });
      revocations = r.revocations;
      broker.tokens_revoked = r.revocations.filter((x) => x.revoked).length;
      broker.secrets_purged = r.purged;
    } catch (e) {
      broker.error = `broker unreachable (${(e as Error).message}): in-memory tokens NOT wiped. Stop the broker process now.`;
    }
  } else broker.error = "no broker connection: in-memory tokens NOT wiped. Stop the broker process now.";

  const checklist: ChecklistItem[] = [];
  for (const { id } of (await pool.query("select id from connectors order by id")).rows as { id: string }[]) {
    let conn;
    try {
      conn = await loadActiveConnector(pool, id, opts.env);
    } catch {
      checklist.push({ connector_id: id, source: "?", auth_type: "?", refs: [], action: "revoke_manually", detail: "config unreadable: revoke its credentials at the provider" });
      continue;
    }
    const refs = credentialRefs(conn);
    const rev = revocations.find((r) => r.connectorId === id);
    const hint = conn.credential?.revoke_hint;
    let action: ChecklistItem["action"];
    let detail: string;
    if (conn.connection.auth.type === "none") [action, detail] = ["nothing_to_revoke", "no credential"];
    else if (rev?.revoked) [action, detail] = ["revoked_by_api", `${rev.detail}. Also rotate the client credential at the provider if a hub breach is suspected`];
    else [action, detail] = ["revoke_manually", `${hint ?? `revoke ${refs.join(", ")} in the ${conn.metadata.source} console`}${rev ? ` (${rev.detail})` : ""}`];
    checklist.push({ connector_id: id, source: conn.metadata.source, auth_type: conn.connection.auth.type, refs, action, detail });
  }

  await pool.query("insert into alerts (connector_id, kind, message) values (null, 'panic', $1)", [
    `panic by ${actor}: ${disabled.length} connectors disabled, ${broker.tokens_revoked} tokens revoked${broker.error ? `; ${broker.error}` : ""}`,
  ]);
  return { at, disabled, queued_runs_cancelled: cancelled, ...(queuedRunsError ? { queued_runs_error: queuedRunsError } : {}), broker, checklist };
}
