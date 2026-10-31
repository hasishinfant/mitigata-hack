// Whitelisted transforms. Pure functions; throw TransformError on bad input.
import type { TRANSFORMS } from "../config/schema.ts";

export type TransformName = (typeof TRANSFORMS)[number];
export class TransformError extends Error {}

const NAIVE_DATETIME = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;

/** Normalise a date-ish value to an ISO 8601 UTC string. Timezone-less datetimes are treated as UTC. */
export function toIso(v: unknown): string {
  let ms: number;
  if (typeof v === "number") {
    ms = Math.abs(v) >= 1e11 ? v : v * 1000; // heuristic: >= 1e11 means milliseconds
  } else if (typeof v === "string") {
    const s = v.trim();
    if (/^-?\d+(\.\d+)?$/.test(s)) return toIso(Number(s));
    ms = Date.parse(NAIVE_DATETIME.test(s) ? `${s.replace(" ", "T")}Z` : s);
  } else if (v instanceof Date) {
    ms = v.getTime();
  } else {
    throw new TransformError(`cannot convert ${typeof v} to a date`);
  }
  if (!Number.isFinite(ms)) throw new TransformError(`not a valid date: ${JSON.stringify(v)}`);
  return new Date(ms).toISOString();
}

function fromEpoch(v: unknown, factor: number): string {
  const n = typeof v === "string" ? Number(v.trim()) : v;
  if (typeof n !== "number" || !Number.isFinite(n)) throw new TransformError(`not an epoch number: ${JSON.stringify(v)}`);
  return new Date(n * factor).toISOString();
}

function str(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  throw new TransformError(`expected text, got ${Array.isArray(v) ? "array" : typeof v}`);
}

export function cvssToSeverity(v: unknown): string {
  const n = typeof v === "string" ? Number(v.trim()) : v;
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0 || n > 10) throw new TransformError(`not a CVSS score (0-10): ${JSON.stringify(v)}`);
  if (n === 0) return "info";
  if (n < 4) return "low";
  if (n < 7) return "medium";
  if (n < 9) return "high";
  return "critical";
}

const SCALAR: Record<Exclude<TransformName, "first">, (v: unknown) => unknown> = {
  to_iso8601: toIso,
  from_epoch_ms: (v) => fromEpoch(v, 1),
  from_epoch_s: (v) => fromEpoch(v, 1000),
  lowercase: (v) => str(v).toLowerCase(),
  uppercase: (v) => str(v).toUpperCase(),
  trim: (v) => str(v).trim(),
  to_number: (v) => {
    const n = typeof v === "number" ? v : Number(str(v).trim());
    if (!Number.isFinite(n) || (typeof v === "string" && v.trim() === "")) throw new TransformError(`not a number: ${JSON.stringify(v)}`);
    return n;
  },
  cvss_to_severity: cvssToSeverity,
};

/** Apply one transform. `first` takes the first element of an array; others apply element-wise to arrays. */
export function applyTransform(name: TransformName, v: unknown): unknown {
  if (v === undefined || v === null) return v;
  if (name === "first") return Array.isArray(v) ? v.find((x) => x !== undefined && x !== null) : v;
  const fn = SCALAR[name];
  return Array.isArray(v) ? v.map((x) => (x === undefined || x === null ? x : fn(x))) : fn(v);
}
