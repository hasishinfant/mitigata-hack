// Pagination strategies. Each turns "the page we just got" into "the next request to send" (or null).
// The next request (URL + optional JSON body) is the whole resume state, so checkpoints are uniform.
import type { StreamConfig } from "../../config/schema.ts";
import { resolvePath } from "../../mapping/paths.ts";

export type PageRequest = { url: URL; body?: Record<string, unknown> };
export type PageContext = { req: PageRequest; headers: Record<string, string>; body: unknown; records: number };
export interface Paginator {
  start(base: PageRequest): PageRequest;
  next(page: PageContext): PageRequest | null;
}
type Pg = StreamConfig["pagination"];
type ParamsIn = "query" | "body";

/** Parse an RFC 8288 Link header into rel -> URL. */
export function parseLinkHeader(header: string | undefined, base: URL): Record<string, URL> {
  const out: Record<string, URL> = {};
  if (!header) return out;
  for (const part of header.split(/,(?=\s*<)/)) {
    const m = /<([^>]*)>(.*)/.exec(part.trim());
    if (!m) continue;
    const rel = /;\s*rel\s*=\s*"?([^";]+)"?/i.exec(m[2]!)?.[1];
    if (!rel) continue;
    try {
      for (const r of rel.trim().split(/\s+/)) out[r.toLowerCase()] = new URL(m[1]!, base);
    } catch {
      /* ignore malformed link */
    }
  }
  return out;
}

const num = (v: unknown): number | undefined => {
  const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v;
  return typeof n === "number" && Number.isFinite(n) ? n : undefined;
};

/** Read / write a paging parameter in the query string or the JSON body. Always returns a copy. */
function getParam(req: PageRequest, where: ParamsIn, name: string): unknown {
  return where === "body" ? req.body?.[name] : req.url.searchParams.get(name);
}
function withParams(req: PageRequest, where: ParamsIn, params: Record<string, string | number>): PageRequest {
  if (where === "body") return { url: new URL(req.url), body: { ...req.body, ...params } };
  const url = new URL(req.url);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  return { url, ...(req.body ? { body: req.body } : {}) };
}

export function createPaginator(pg: Pg, paramsIn: ParamsIn = "query"): Paginator {
  switch (pg.type) {
    case "none":
      return { start: (b) => b, next: () => null };

    case "link_header": {
      const rel = (pg.rel ?? "next").toLowerCase();
      return {
        start: (b) => b,
        next: ({ req, headers, records }) => {
          if (records === 0) return null;
          const next = parseLinkHeader(headers.link, req.url)[rel];
          return next && next.href !== req.url.href ? { url: next, ...(req.body ? { body: req.body } : {}) } : null;
        },
      };
    }

    case "body_link":
      return {
        start: (b) => b,
        next: ({ req, body, records }) => {
          if (records === 0) return null;
          const raw = resolvePath(body, pg.next_path);
          if (typeof raw !== "string" || raw === "") return null;
          let next: URL;
          try {
            next = new URL(raw, req.url);
          } catch {
            return null;
          }
          return next.href !== req.url.href ? { url: next, ...(req.body ? { body: req.body } : {}) } : null;
        },
      };

    case "offset": {
      const start = pg.start ?? 0;
      return {
        start: (b) => withParams(b, paramsIn, { [pg.offset_param]: start, [pg.limit_param]: pg.limit }),
        next: ({ req, body, records }) => {
          if (records === 0) return null;
          const offset = num(getParam(req, paramsIn, pg.offset_param)) ?? start;
          const nextOffset = offset + records; // advance by what we actually got (providers may cap page size)
          if (pg.total_path) {
            const total = num(resolvePath(body, pg.total_path));
            if (total === undefined || nextOffset >= total) return null;
          } else if (records < pg.limit) return null; // no total: a short page is the last page
          return withParams(req, paramsIn, { [pg.offset_param]: nextOffset });
        },
      };
    }

    case "page_number": {
      const start = pg.start ?? 1;
      return {
        start: (b) => withParams(b, paramsIn, { [pg.page_param]: start, [pg.size_param]: pg.size }),
        next: ({ req, records }) => {
          if (records === 0) return null; // stop_when: empty_page
          const page = num(getParam(req, paramsIn, pg.page_param)) ?? start;
          return withParams(req, paramsIn, { [pg.page_param]: page + 1 });
        },
      };
    }

    case "cursor":
      return {
        start: (b) => b,
        next: ({ req, headers, body, records }) => {
          if (pg.is_last_path && resolvePath(body, pg.is_last_path) === true) return null;
          if (pg.stop_when !== "is_last_path" && records === 0) return null;
          const raw = pg.token_path ? resolvePath(body, pg.token_path) : headers[(pg.token_header ?? "").toLowerCase()];
          if (raw === undefined || raw === null || raw === "") return null;
          const token = String(raw);
          if (String(getParam(req, paramsIn, pg.token_param) ?? "") === token) return null; // repeated cursor: stop, don't loop
          return withParams(req, paramsIn, { [pg.token_param]: token });
        },
      };
  }
}
