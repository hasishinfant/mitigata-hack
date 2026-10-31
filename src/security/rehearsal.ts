// Non-destructive incident-response rehearsal. It verifies operational dependencies and
// assembles the panic checklist without changing connector, queue, broker, or secret state.
import type pg from "pg";
import type { BrokerAdmin } from "../broker/remote.ts";
import { verifyLedger, type LedgerCheck } from "../broker/ledger.ts";
import { listConnectorIds } from "../store/connectors.ts";
import { getPosture, type Level, type Posture } from "./posture.ts";

export type RehearsalCheck = {
  name: string;
  status: "pass" | "attention" | "fail" | "not_tested";
  detail: string;
};

export type RehearsalConnector = {
  id: string;
  status: string;
  risk: Level | null;
  flags: string[];
  credentials: string[];
  revocation: "api_revocation_declared" | "manual_provider_revocation" | "nothing_to_revoke" | "posture_unavailable";
  revoke_hint: string | null;
  error?: string;
};

export type RehearsalReport = {
  generated_at: string;
  non_destructive: true;
  ready: boolean;
  checks: RehearsalCheck[];
  connectors: RehearsalConnector[];
  panic_plan: {
    disable_connectors: string[];
    cancel_queued_runs: true;
    clear_broker_token_cache: true;
    purge_stored_secrets: false;
  };
};

export async function runRehearsal(opts: {
  pool: pg.Pool;
  broker: Pick<BrokerAdmin, "ping">;
  env?: Record<string, string | undefined>;
  loadPosture?: typeof getPosture;
  checkLedger?: typeof verifyLedger;
}): Promise<RehearsalReport> {
  const generatedAt = new Date().toISOString();
  const ids = await listConnectorIds(opts.pool);
  const connectors: RehearsalConnector[] = [];
  const checks: RehearsalCheck[] = [];
  const posture = opts.loadPosture ?? getPosture;
  const ledger = opts.checkLedger ?? verifyLedger;

  for (const { id, status } of ids) {
    try {
      const p: Posture = await posture(opts.pool, id, opts.env);
      connectors.push({
        id,
        status,
        risk: p.risk,
        flags: p.flags.map((f) => `${f.level}: ${f.message}`),
        credentials: p.credentials.map((c) => c.ref),
        revocation: p.auth_type === "none"
          ? "nothing_to_revoke"
          : p.auth_type === "oauth2_client_credentials" && p.revocable_by_api === true
            ? "api_revocation_declared"
            : "manual_provider_revocation",
        revoke_hint: p.revoke_hint,
      });
    } catch (e) {
      connectors.push({
        id,
        status,
        risk: null,
        flags: [],
        credentials: [],
        revocation: "posture_unavailable",
        revoke_hint: null,
        error: (e as Error).message,
      });
    }
  }

  const brokerReachable = await opts.broker.ping();
  checks.push({
    name: "broker",
    status: brokerReachable ? "pass" : "fail",
    detail: brokerReachable ? "broker is reachable; no tokens were revoked" : "broker is unreachable; panic cannot clear its in-memory token cache",
  });

  let ledgerCheck: LedgerCheck;
  try {
    ledgerCheck = await ledger(opts.pool);
    checks.push({
      name: "audit ledger",
      status: ledgerCheck.ok ? "pass" : "fail",
      detail: ledgerCheck.ok ? `${ledgerCheck.rows} rows verified` : ledgerCheck.problem ?? "ledger verification failed",
    });
  } catch (e) {
    const problem = (e as Error).message;
    ledgerCheck = { ok: false, rows: 0, problem };
    checks.push({ name: "audit ledger", status: "fail", detail: problem });
  }

  const unavailable = connectors.filter((c) => c.risk === null);
  const highRisk = connectors.filter((c) => c.risk === "high");
  checks.push({
    name: "connector posture",
    status: unavailable.length ? "fail" : highRisk.length ? "attention" : "pass",
    detail: unavailable.length
      ? `posture unavailable for ${unavailable.map((c) => c.id).join(", ")}`
      : highRisk.length
        ? `high-risk connectors: ${highRisk.map((c) => c.id).join(", ")}`
        : `${connectors.length} connector posture(s) loaded`,
  });
  checks.push({
    name: "alert delivery",
    status: "not_tested",
    detail: "no test message was sent; use the alerts command/API to review delivery history",
  });

  return {
    generated_at: generatedAt,
    non_destructive: true,
    ready: brokerReachable && ledgerCheck.ok && unavailable.length === 0,
    checks,
    connectors,
    panic_plan: {
      disable_connectors: connectors.filter((c) => c.status !== "disabled").map((c) => c.id),
      cancel_queued_runs: true,
      clear_broker_token_cache: true,
      purge_stored_secrets: false,
    },
  };
}
