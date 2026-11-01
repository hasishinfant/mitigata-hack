// Schema fingerprint of raw provider records: which paths exist and with which JSON types, recursively.
// Paths are JSON-pointer-like ("/cve/metrics/[]/cvssData/baseScore"); array elements collapse to "[]".
// Compared against the last published sync of the same stream to tell additive changes (new fields: fine)
// from breaking ones (a field the mapping reads disappeared or changed type). Provider-neutral.
import { createHash } from "node:crypto";
import type { FieldSpec } from "../config/schema.ts";
import { parsePath } from "../mapping/paths.ts";

export type Shape = Record<string, string[]>; // path -> sorted JSON types seen there
export type SchemaEvidence = { fingerprint: string; sampled: number; paths: number; shape: Shape };
export type SchemaDiff = { breaking: string[]; added: number; removed: number };

const SAMPLE_RECORDS = 200; // records sampled per run (first N)
const MAX_DEPTH = 8;
const MAX_PATHS = 2000;
const ARRAY_SAMPLE = 20; // elements looked at per array

const esc = (k: string) => k.replace(/~/g, "~0").replace(/\//g, "~1");
const typeOf = (v: unknown) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);

export class ShapeCollector {
  private readonly paths = new Map<string, Set<string>>();
  private sampled = 0;

  add(raw: unknown): void {
    if (this.sampled >= SAMPLE_RECORDS) return;
    this.sampled++;
    this.walk(raw, "", 0);
  }

  private walk(v: unknown, path: string, depth: number): void {
    if (path) {
      let set = this.paths.get(path);
      if (!set) {
        if (this.paths.size >= MAX_PATHS) return;
        this.paths.set(path, (set = new Set()));
      }
      set.add(typeOf(v));
    }
    if (depth >= MAX_DEPTH || v === null || typeof v !== "object") return;
    if (Array.isArray(v)) for (const x of v.slice(0, ARRAY_SAMPLE)) this.walk(x, `${path}/[]`, depth + 1);
    else for (const [k, x] of Object.entries(v)) this.walk(x, `${path}/${esc(k)}`, depth + 1);
  }

  result(): SchemaEvidence {
    const shape: Shape = Object.fromEntries([...this.paths.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([p, t]) => [p, [...t].sort()]));
    const fingerprint = createHash("sha256").update(JSON.stringify(shape)).digest("hex");
    return { fingerprint, sampled: this.sampled, paths: Object.keys(shape).length, shape };
  }
}

/** The fingerprint path a mapping path reads ("_source[\"kibana.alert.severity\"]" -> "/_source/kibana.alert.severity"). */
export function pointerOf(mappingPath: string): string {
  const segs = parsePath(mappingPath);
  return segs.map((s) => (s.kind === "key" ? `/${esc(s.key)}` : "/[]")).join("");
}

/** Paths the mapping depends on (field paths and concat parts; attribute picks are optional extras, not included). */
export function mappedPointers(mapping: Record<string, FieldSpec>): string[] {
  const out = new Set<string>();
  for (const [field, spec] of Object.entries(mapping)) {
    if (field === "attributes") continue;
    const paths = spec.path === undefined ? [] : Array.isArray(spec.path) ? spec.path : [spec.path];
    for (const p of paths) out.add(pointerOf(p));
    for (const c of spec.concat ?? []) if (typeof c === "string") out.add(pointerOf(c));
  }
  return [...out].filter(Boolean).sort();
}

/**
 * Compare against the baseline. Breaking: a mapped path the baseline had is gone, or its non-null types changed.
 * For alternatives (path: [a, b]) a missing alternative is only breaking if none of them remains.
 */
export function diffSchema(baseline: Shape, current: Shape, mapping: Record<string, FieldSpec>): SchemaDiff {
  const breaking: string[] = [];
  const nonNull = (t: string[] | undefined) => (t ?? []).filter((x) => x !== "null").sort().join("|");
  for (const [field, spec] of Object.entries(mapping)) {
    if (field === "attributes") continue;
    const alts = (spec.path === undefined ? [] : Array.isArray(spec.path) ? spec.path : [spec.path]).map(pointerOf);
    const parts = (spec.concat ?? []).filter((c): c is string => typeof c === "string").map(pointerOf);
    const groups = alts.length ? [alts] : parts.map((p) => [p]);
    for (const group of groups) {
      const known = group.filter((p) => baseline[p]);
      if (!known.length) continue; // the baseline never had it: nothing to compare
      const present = group.filter((p) => current[p]);
      if (!present.length) {
        breaking.push(`${field}: ${group.join(" | ")} no longer present`);
        continue;
      }
      for (const p of present)
        if (baseline[p] && nonNull(baseline[p]) && nonNull(current[p]) && nonNull(baseline[p]) !== nonNull(current[p]))
          breaking.push(`${field}: ${p} changed type ${nonNull(baseline[p])} -> ${nonNull(current[p])}`);
    }
  }
  const added = Object.keys(current).filter((p) => !baseline[p]).length;
  const removed = Object.keys(baseline).filter((p) => !current[p]).length;
  return { breaking, added, removed };
}
