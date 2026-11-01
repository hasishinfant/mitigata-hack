// Sync Integrity Receipt: a canonical JSON record of what a run fetched, how it was judged and what was published.
// digest = sha256(canonical JSON of the body). The broker anchors the digest in the hash-chained audit ledger, so a
// receipt changed afterwards no longer matches its anchor. A receipt is evidence of what IntegrateX saw and decided;
// it does not prove the provider's data is true or complete.
import { createHash } from "node:crypto";

/** Deterministic JSON: object keys sorted at every level; undefined dropped. */
export function canonicalJson(v: unknown): string {
  return JSON.stringify(sortDeep(v));
}
function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object" && !(v instanceof Date)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) {
      const x = (v as Record<string, unknown>)[k];
      if (x !== undefined) out[k] = sortDeep(x);
    }
    return out;
  }
  return v;
}

export const receiptDigest = (body: unknown): string => createHash("sha256").update(canonicalJson(body)).digest("hex");

/** What a receipt never claims. Fixed text, part of every body. */
export const NOT_CLAIMED = [
  "that the provider's data is true",
  "that the provider returned everything it holds beyond what its paging signalled",
  "that records changed upstream after they were fetched are reflected",
];
