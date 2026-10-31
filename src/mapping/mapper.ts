// Maps one raw provider record to the common schema using a validated mapping spec.
// Never throws for bad data: returns { ok: false, errors } so the caller can quarantine.
import { isIP } from "node:net";
import { SEVERITIES, type Entity, type FieldSpec } from "../config/schema.ts";
import { resolvePath } from "./paths.ts";
import { applyTransform, toIso, TransformError } from "./transforms.ts";

export type MappedRecord = { sourceId: string; fields: Record<string, unknown>; attributes: Record<string, unknown> };
export type MapResult =
  | { ok: true; record: MappedRecord; present: string[] }
  | { ok: false; errors: string[]; present: string[] };
// present: fields for which the provider supplied a value (used for schema-drift hit rates)

const DATE_FIELDS = new Set(["last_login", "last_seen", "timestamp"]);
const ALWAYS_REQUIRED: Record<Entity, string[]> = { user: ["id"], device: ["id"], event: ["id", "type"] };

const isEmpty = (v: unknown) => v === undefined || v === null || v === "" || (Array.isArray(v) && v.length === 0);

function sourceValue(raw: unknown, spec: FieldSpec): unknown {
  if (spec.const !== undefined) return spec.const;
  if (spec.path !== undefined) {
    const paths = Array.isArray(spec.path) ? spec.path : [spec.path];
    for (const p of paths) {
      const v = resolvePath(raw, p);
      if (!isEmpty(v)) return v;
    }
    return undefined;
  }
  if (spec.concat) {
    let anyPath = false;
    const parts = spec.concat.map((item) => {
      if (typeof item !== "string") return item.lit;
      const v = resolvePath(raw, item);
      if (isEmpty(v)) return "";
      anyPath = true;
      return Array.isArray(v) ? v.join(",") : typeof v === "object" ? JSON.stringify(v) : String(v);
    });
    const s = parts.join("").trim();
    return anyPath && s !== "" ? s : undefined;
  }
  return undefined;
}

/** Returns the final value and whether the provider actually supplied one (defaults don't count: drift detection). */
function mapField(raw: unknown, field: string, spec: FieldSpec): { value: unknown; hit: boolean } {
  let v = sourceValue(raw, spec);
  const hit = spec.const !== undefined || !isEmpty(v);
  const transforms = spec.transform === undefined ? [] : Array.isArray(spec.transform) ? spec.transform : [spec.transform];
  for (const t of transforms) v = applyTransform(t, v);
  if (spec.map_enum && !isEmpty(v)) {
    if (Array.isArray(v) || typeof v === "object") throw new TransformError("map_enum needs a single value (add transform: first)");
    const key = String(v);
    v = Object.hasOwn(spec.map_enum, key) ? spec.map_enum[key] : undefined;
  }
  if (isEmpty(v) && spec.default !== undefined) v = spec.default;
  if (DATE_FIELDS.has(field) && !isEmpty(v)) v = toIso(v);
  return { value: v, hit };
}

export function mapRecord(raw: unknown, entity: Entity, mapping: Record<string, FieldSpec>): MapResult {
  const errors: string[] = [];
  const present: string[] = [];
  const fields: Record<string, unknown> = {};
  let attributes: Record<string, unknown> = {};

  for (const [field, spec] of Object.entries(mapping)) {
    if (field === "attributes") {
      attributes = {};
      for (const p of spec.pick ?? []) {
        const v = resolvePath(raw, p);
        if (v !== undefined) attributes[p] = v;
      }
      continue;
    }
    let v: unknown;
    try {
      const out = mapField(raw, field, spec);
      v = out.value;
      if (out.hit) present.push(field);
    } catch (e) {
      present.push(field); // a value was there, it just failed to convert
      errors.push(`${field}: ${(e as Error).message}`);
      continue;
    }
    if (isEmpty(v)) {
      if (spec.required || ALWAYS_REQUIRED[entity].includes(field)) errors.push(`${field}: required value missing (${describe(spec)})`);
      continue;
    }
    if (Array.isArray(v) || (typeof v === "object" && v !== null)) {
      errors.push(`${field}: resolved to ${Array.isArray(v) ? "multiple values" : "an object"}; add transform: first or use a deeper path`);
      continue;
    }
    fields[field] = v;
  }

  for (const f of ALWAYS_REQUIRED[entity]) if (!(f in mapping)) errors.push(`${f}: no mapping defined`);
  if (fields.severity !== undefined && !(SEVERITIES as readonly string[]).includes(String(fields.severity)))
    errors.push(`severity: "${String(fields.severity)}" is not one of ${SEVERITIES.join(", ")}`);
  if (fields.ip !== undefined && isIP(String(fields.ip)) === 0) errors.push(`ip: "${String(fields.ip)}" is not an IP address`);
  if (errors.length) return { ok: false, errors, present };

  const { id, ...rest } = fields;
  return { ok: true, record: { sourceId: String(id), fields: rest, attributes }, present };
}

function describe(spec: FieldSpec): string {
  if (spec.path !== undefined) return `path ${Array.isArray(spec.path) ? spec.path.join(" | ") : spec.path}`;
  if (spec.concat) return "concat";
  return "const";
}
