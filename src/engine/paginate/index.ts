// Pagination strategies. Each turns "the page we just got" into "the next request to send" (or null).
// The next request (URL + optional JSON body) is the whole resume state, so checkpoints are uniform.
import type { StreamConfig } from "../../config/schema.ts";
import { resolvePath } from "../../mapping/paths.ts";

export type PageRequest = { url: URL; body?: Record<string, unknown> };
export type PageContext = { req: PageRequest; headers: Record<string, string>; body: unknown; records: number };
/**
 * What comes after a page: another request, or the end of the stream and why.
 *   complete: the provider signalled the last page in the way the config declares.
 *   anomaly:  paging stopped, but not in a way that proves we saw every page (repeated cursor, missing
 *             total, a "next" link pointing back at the same page). The run must not count as complete.
 */
export type PageStep = { next: PageRequest } | { next: null; end: "complete" } | { next: null; end: "anomaly"; reason: string };
export interface Paginator {
  start(base: PageRequest): PageRequest;
  step(page: PageContext): PageStep;
  /** Next request or null (any kind of end). Kept for callers that only peek, like test connection. */
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

const go = (next: PageRequest): PageStep => ({ next });
const done: PageStep = { next: null, end: "complete" };
const anomaly = (reason: string): PageStep => ({ next: null, end: "anomaly", reason });
const keep = (req: PageRequest) => (req.body ? { body: req.body } : {});

export function createPaginator(pg: Pg, paramsIn: ParamsIn = "query"): Paginator {
  const p = strategy(pg, paramsIn);
  return { start: p.start, step: p.step, next: (page) => p.step(page).next };
}

function strategy(pg: Pg, paramsIn: ParamsIn): Pick<Paginator, "start" | "step"> {
  switch (pg.type) {
    case "none":
      return { start: (b) => b, step: () => done };

    case "link_header": {
      const rel = (pg.rel ?? "next").toLowerCase();
      return {
        start: (b) => b,
        step: ({ req, headers, records }) => {
          if (records === 0) return done;
          const next = parseLinkHeader(headers.link, req.url)[rel];
          if (!next) return done;
          if (next.href === req.url.href) return anomaly(`Link rel="${rel}" points at the page just fetched`);
          return go({ url: next, ...keep(req) });
        },
      };
    }

    case "body_link":
      return {
        start: (b) => b,
        step: ({ req, body, records }) => {
          if (records === 0) return done;
          const raw = resolvePath(body, pg.next_path);
          if (raw === undefined || raw === null || raw === "") return done;
          if (typeof raw !== "string") return anomaly(`${pg.next_path} is ${typeof raw}, expected a URL string`);
          let next: URL;
          try {
            next = new URL(raw, req.url);
          } catch {
            return anomaly(`${pg.next_path} is not a valid URL`);
          }
          if (next.href === req.url.href) return anomaly(`${pg.next_path} points at the page just fetched`);
          return go({ url: next, ...keep(req) });
        },
      };

    case "offset": {
      const start = pg.start ?? 0;
      return {
        start: (b) => withParams(b, paramsIn, { [pg.offset_param]: start, [pg.limit_param]: pg.limit }),
        step: ({ req, body, records }) => {
          const offset = num(getParam(req, paramsIn, pg.offset_param)) ?? start;
          const nextOffset = offset + records; // advance by what we actually got (providers may cap page size)
          if (pg.total_path) {
            const total = num(resolvePath(body, pg.total_path));
            if (total === undefined) return anomaly(`total_path "${pg.total_path}" missing or not a number: can't tell whether more pages exist`);
            if (nextOffset >= total) return done;
            if (records === 0) return anomaly(`empty page at ${pg.offset_param}=${offset}, but ${pg.total_path} says ${total}`);
          } else if (records < pg.limit) return done; // no total: a short (or empty) page is the last page
          return go(withParams(req, paramsIn, { [pg.offset_param]: nextOffset }));
        },
      };
    }

    case "page_number": {
      const start = pg.start ?? 1;
      return {
        start: (b) => withParams(b, paramsIn, { [pg.page_param]: start, [pg.size_param]: pg.size }),
        step: ({ req, records }) => {
          if (records === 0) return done; // stop_when: empty_page
          const page = num(getParam(req, paramsIn, pg.page_param)) ?? start;
          return go(withParams(req, paramsIn, { [pg.page_param]: page + 1 }));
        },
      };
    }

    case "cursor":
      return {
        start: (b) => b,
        step: ({ req, headers, body, records }) => {
          const lastFlag = pg.is_last_path ? resolvePath(body, pg.is_last_path) : undefined;
          if (lastFlag === true) return done;
          if (pg.stop_when !== "is_last_path" && records === 0) return done;
          const raw = pg.token_path ? resolvePath(body, pg.token_path) : headers[(pg.token_header ?? "").toLowerCase()];
          if (raw === undefined || raw === null || raw === "") {
            if (pg.stop_when === "is_last_path")
              return anomaly(`no next cursor, but ${pg.is_last_path} is ${JSON.stringify(lastFlag) ?? "missing"} (expected true on the last page)`);
            return done;
          }
          const token = String(raw);
          if (String(getParam(req, paramsIn, pg.token_param) ?? "") === token) return anomaly("provider returned the same cursor again");
          return go(withParams(req, paramsIn, { [pg.token_param]: token }));
        },
      };
  }
}
