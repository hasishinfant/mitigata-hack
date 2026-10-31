// Path resolver for mapping configs. No eval, no expression language.
// Syntax: `$` (root), `a.b.c`, `a[0]`, `a[*]`, `a["odd key"]`, optional leading `$.`.
// Max depth 10 segments.

export type Segment = { kind: "key"; key: string } | { kind: "index"; index: number } | { kind: "all" };

export const MAX_PATH_DEPTH = 10;

export class PathSyntaxError extends Error {}

const KEY_RE = /^[A-Za-z_@$][A-Za-z0-9_\-@$]*/;

const cache = new Map<string, Segment[]>();

export function parsePath(path: string): Segment[] {
  const hit = cache.get(path);
  if (hit) return hit;
  const segs = parseUncached(path);
  if (cache.size < 5000) cache.set(path, segs);
  return segs;
}

function parseUncached(path: string): Segment[] {
  if (typeof path !== "string" || path.trim() === "") throw new PathSyntaxError("empty path");
  let s = path.trim();
  if (s === "$") return [];
  if (s.startsWith("$.")) s = s.slice(2);
  else if (s.startsWith("$[")) s = s.slice(1);
  const segs: Segment[] = [];
  let i = 0;
  let expectKey = true;
  while (i < s.length) {
    const ch = s[i];
    if (ch === "[") {
      const close = s.indexOf("]", i);
      if (close === -1) throw new PathSyntaxError(`unclosed '[' at position ${i} in "${path}"`);
      const inner = s.slice(i + 1, close).trim();
      if (inner === "*") segs.push({ kind: "all" });
      else if (/^\d+$/.test(inner)) segs.push({ kind: "index", index: Number(inner) });
      else if (/^"[^"]*"$/.test(inner) || /^'[^']*'$/.test(inner)) segs.push({ kind: "key", key: inner.slice(1, -1) });
      else throw new PathSyntaxError(`bad index [${inner}] in "${path}" (use [0], [*] or ["key"])`);
      i = close + 1;
      expectKey = false;
    } else if (ch === ".") {
      if (expectKey) throw new PathSyntaxError(`unexpected '.' at position ${i} in "${path}"`);
      i++;
      expectKey = true;
      if (i >= s.length) throw new PathSyntaxError(`path "${path}" ends with '.'`);
    } else {
      if (!expectKey) throw new PathSyntaxError(`expected '.' or '[' at position ${i} in "${path}"`);
      const m = KEY_RE.exec(s.slice(i));
      if (!m) throw new PathSyntaxError(`bad character '${ch}' at position ${i} in "${path}"`);
      segs.push({ kind: "key", key: m[0] });
      i += m[0].length;
      expectKey = false;
    }
    if (segs.length > MAX_PATH_DEPTH) throw new PathSyntaxError(`path "${path}" deeper than ${MAX_PATH_DEPTH}`);
  }
  return segs;
}

export function hasWildcard(path: string): boolean {
  return parsePath(path).some((s) => s.kind === "all");
}

/**
 * Resolve a path. Without `[*]` returns the value or undefined.
 * With `[*]` returns an array of all matches (undefined matches dropped).
 */
export function resolvePath(root: unknown, path: string): unknown {
  const segs = parsePath(path);
  const multi = segs.some((s) => s.kind === "all");
  let current: unknown[] = [root];
  for (const seg of segs) {
    const next: unknown[] = [];
    for (const v of current) {
      if (v === null || v === undefined) continue;
      if (seg.kind === "all") {
        if (Array.isArray(v)) next.push(...v);
      } else if (seg.kind === "index") {
        if (Array.isArray(v) && seg.index < v.length) next.push(v[seg.index]);
      } else if (typeof v === "object" && !Array.isArray(v) && Object.hasOwn(v as object, seg.key)) {
        next.push((v as Record<string, unknown>)[seg.key]);
      }
    }
    current = next;
  }
  if (multi) return current.filter((v) => v !== undefined);
  return current[0];
}
