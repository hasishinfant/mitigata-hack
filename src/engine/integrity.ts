// Integrity evaluator: decides whether a sync's staged records may be published, from evidence the run collected.
// Pure and provider-neutral. Decisions:
//   verified        complete, within quality limits: publish the staged records
//   verified_empty  complete and the provider explicitly returned no records (envelope present on every page)
//   held            complete, but something needs a human (schema change, too much quarantine, too few records):
//                   staged records wait for `ix approve` / `ix discard`; nothing is published
//   incomplete      not finished (failure with a resumable checkpoint, request/record cap, lost lock): staged records
//                   are kept and the next run continues the same sync
//   rejected        cannot be completed as is (pagination anomaly, failure with no position to resume from):
//                   staged records are discarded
import type { RunStatus } from "./runner.ts";

export type Decision = "verified" | "verified_empty" | "held" | "incomplete" | "rejected";

export type IntegrityInput = {
  status: RunStatus;
  completed: boolean; // the provider signalled the last page, in the way the config declares
  stopReason?: string; // a per-run cap stopped it; continues next run
  lastError?: string;
  resumable: boolean; // a checkpoint for this sync survives the run
  lockLost: boolean;
  seen: number; // records the provider returned in this sync (all runs)
  accepted: number;
  quarantined: number;
  drift: string[]; // field hit-rate drift (runner)
  schemaBreaking: string[]; // fingerprint diff against the last published sync
  maxQuarantineRatio: number;
  minRecords: number;
};

export type IntegrityVerdict = { decision: Decision; publish: boolean; discard: boolean; reasons: string[] };

export const DEFAULT_MAX_QUARANTINE_RATIO = 0.1;

export function evaluateIntegrity(i: IntegrityInput): IntegrityVerdict {
  const v = (decision: Decision, reasons: string[]): IntegrityVerdict => ({
    decision, reasons, publish: decision === "verified" || decision === "verified_empty", discard: decision === "rejected",
  });
  if (i.lockLost) return v("incomplete", ["run lock lost: this run committed nothing more; the next run continues the sync"]);
  if (i.status === "failed" || i.status === "auth_failed") {
    const why = i.lastError ?? i.status;
    return i.resumable ? v("incomplete", [`run failed (${why}); staged pages kept, the next run resumes`]) : v("rejected", [`run failed (${why}) with no position to resume from; staged pages discarded`]);
  }
  if (i.stopReason) return v("incomplete", [i.stopReason]);
  if (!i.completed) return v("incomplete", ["the provider did not signal the last page"]);

  const hold: string[] = [];
  if (i.drift.length) hold.push(...i.drift.map((d) => `schema drift: ${d}`));
  if (i.schemaBreaking.length) hold.push(...i.schemaBreaking.map((d) => `schema change: ${d}`));
  if (i.seen > 0 && i.quarantined / i.seen > i.maxQuarantineRatio)
    hold.push(`${i.quarantined} of ${i.seen} records quarantined (${Math.round((i.quarantined / i.seen) * 100)}% > ${Math.round(i.maxQuarantineRatio * 100)}% allowed)`);
  if (i.accepted < i.minRecords) hold.push(`${i.accepted} records accepted, expected at least ${i.minRecords}`);
  if (hold.length) return v("held", hold);
  if (i.seen === 0) return v("verified_empty", ["complete; the provider returned no records (envelope present on every page)"]);
  return v("verified", [`complete: ${i.accepted} records accepted${i.quarantined ? `, ${i.quarantined} quarantined (within limit)` : ""}`]);
}
