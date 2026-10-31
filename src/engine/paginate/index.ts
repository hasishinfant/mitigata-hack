// Pagination strategies. Each turns "the page we just got" into "the next URL to fetch" (or null).
// The next URL is the whole resume state, which makes checkpoints uniform across styles.
import type { StreamConfig } from "../../config/schema.ts";
import { resolvePath } from "../../mapping/paths.ts";

export type PageContext = { url: URL; headers: Record<string, string>; body: unknown; records: number };
export interface Paginator {
  start(base: URL): URL;
  next(page: PageContext): URL | null;
}
type Pg = StreamConfig["pagination"];

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
  const n = typeof v === "string" ? Number(v) : v;
  return typeof n === "number" && Number.isFinite(n) ? n : undefined;
};

export function createPaginator(pg: Pg): Paginator {
  switch (pg.type) {
    case "none":
      return { start: (b) => b, next: () => null };

    case "link_header": {
      const rel = (pg.rel ?? "next").toLowerCase();
      return {
        start: (b) => b,
        next: ({ url, headers, records }) => {
          if (records === 0) return null;
          const next = parseLinkHeader(headers.link, url)[rel];
          return next && next.href !== url.href ? next : null;
        },
      };
    }

    case "offset": {
      const start = pg.start ?? 0;
      return {
        start: (b) => {
          const u = new URL(b);
          u.searchParams.set(pg.offset_param, String(start));
          u.searchParams.set(pg.limit_param, String(pg.limit));
          return u;
        },
        next: ({ url, body, records }) => {
          if (records === 0) return null;
          const offset = num(url.searchParams.get(pg.offset_param)) ?? start;
          const total = num(resolvePath(body, pg.total_path));
          const nextOffset = offset + Math.max(records, 1); // advance by what we actually got (providers may cap page size)
          if (total === undefined || nextOffset >= total) return null;
          const u = new URL(url);
          u.searchParams.set(pg.offset_param, String(nextOffset));
          return u;
        },
      };
    }

    case "page_number": {
      const start = pg.start ?? 1;
      return {
        start: (b) => {
          const u = new URL(b);
          u.searchParams.set(pg.page_param, String(start));
          u.searchParams.set(pg.size_param, String(pg.size));
          return u;
        },
        next: ({ url, records }) => {
          if (records === 0) return null; // stop_when: empty_page
          const page = num(url.searchParams.get(pg.page_param)) ?? start;
          const u = new URL(url);
          u.searchParams.set(pg.page_param, String(page + 1));
          return u;
        },
      };
    }

    case "cursor":
      return {
        start: (b) => b,
        next: ({ url, headers, body, records }) => {
          if (pg.is_last_path && resolvePath(body, pg.is_last_path) === true) return null;
          if (pg.stop_when !== "is_last_path" && records === 0) return null;
          const raw = pg.token_path ? resolvePath(body, pg.token_path) : headers[(pg.token_header ?? "").toLowerCase()];
          if (raw === undefined || raw === null || raw === "") return null;
          const token = String(raw);
          if (url.searchParams.get(pg.token_param) === token) return null; // provider repeated the cursor: stop, don't loop
          const u = new URL(url);
          u.searchParams.set(pg.token_param, token);
          return u;
        },
      };
  }
}
