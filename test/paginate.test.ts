import { describe, expect, it } from "vitest";
import { createPaginator, parseLinkHeader } from "../src/engine/paginate/index.ts";

const base = new URL("https://api.example.test/items?x=1");

/** Drive a paginator against a fake provider; returns the URLs fetched. */
function drive(p: ReturnType<typeof createPaginator>, respond: (u: URL) => { headers?: Record<string, string>; body: unknown; records: number }) {
  const fetched: string[] = [];
  let req = p.start({ url: base });
  while (req && fetched.length < 50) {
    fetched.push(req.url.href);
    const r = respond(req.url);
    req = p.next({ req, headers: r.headers ?? {}, body: r.body, records: r.records }) as typeof req;
  }
  return fetched;
}

describe("pagination", () => {
  it("parses Link headers", () => {
    const l = parseLinkHeader('<https://a.test/x?page=2>; rel="next", </x?page=5>; rel="last"', base);
    expect(l.next?.href).toBe("https://a.test/x?page=2");
    expect(l.last?.href).toBe("https://api.example.test/x?page=5");
  });
  it("offset: totalResults 4500 at 2000 per page = exactly 3 calls", () => {
    const p = createPaginator({ type: "offset", offset_param: "startIndex", limit_param: "resultsPerPage", limit: 2000, total_path: "totalResults" });
    const urls = drive(p, (u) => {
      const start = Number(u.searchParams.get("startIndex"));
      return { body: { totalResults: 4500 }, records: Math.min(2000, 4500 - start) };
    });
    expect(urls.map((u) => new URL(u).searchParams.get("startIndex"))).toEqual(["0", "2000", "4000"]);
    expect(new URL(urls[0]!).searchParams.get("x")).toBe("1");
  });
  it("link_header follows next until absent", () => {
    const p = createPaginator({ type: "link_header" });
    const urls = drive(p, (u) => {
      const page = Number(u.searchParams.get("page") ?? 1);
      const headers: Record<string, string> = page < 3 ? { link: `<https://api.example.test/items?page=${page + 1}>; rel="next"` } : {};
      return { headers, body: [], records: 10 };
    });
    expect(urls).toHaveLength(3);
  });
  it("page_number stops on empty page", () => {
    const p = createPaginator({ type: "page_number", page_param: "page", size_param: "size", size: 10 });
    expect(drive(p, (u) => ({ body: [], records: Number(u.searchParams.get("page")) <= 2 ? 10 : 0 }))).toHaveLength(3);
  });
  it("cursor stops on isLast and on a repeated token", () => {
    const p = createPaginator({ type: "cursor", token_path: "next", token_param: "t", stop_when: "is_last_path", is_last_path: "isLast" });
    expect(drive(p, (u) => {
      const n = Number(u.searchParams.get("t") ?? 0);
      return { body: { next: String(n + 1), isLast: n === 2 }, records: 5 };
    })).toHaveLength(3);
    const stuck = createPaginator({ type: "cursor", token_path: "next", token_param: "t" });
    expect(drive(stuck, () => ({ body: { next: "same" }, records: 5 }))).toHaveLength(2);
  });
  it("offset without total stops on a short page", () => {
    const p = createPaginator({ type: "offset", offset_param: "offset", limit_param: "limit", limit: 100 });
    expect(drive(p, (u) => ({ body: {}, records: Number(u.searchParams.get("offset")) < 200 ? 100 : 40 }))).toHaveLength(3);
  });
  it("body_link follows a next URL inside the body (relative or absolute)", () => {
    const p = createPaginator({ type: "body_link", next_path: "nextLink" });
    const urls = drive(p, (u) => {
      const n = Number(u.searchParams.get("skip") ?? 0);
      return { body: n < 2 ? { nextLink: n === 0 ? "/items?skip=1" : "https://api.example.test/items?skip=2" } : {}, records: 5 };
    });
    expect(urls).toEqual(["https://api.example.test/items?x=1", "https://api.example.test/items?skip=1", "https://api.example.test/items?skip=2"]);
  });
  it("paging params can live in a POST body", () => {
    const p = createPaginator({ type: "offset", offset_param: "from", limit_param: "size", limit: 50, total_path: "hits.total.value" }, "body");
    let req: ReturnType<typeof p.start> | null = p.start({ url: base, body: { query: { match_all: {} } } });
    const froms: unknown[] = [];
    while (req) {
      froms.push(req.body?.from);
      expect(req.body?.query).toEqual({ match_all: {} });
      expect(req.url.searchParams.has("from")).toBe(false);
      req = p.next({ req, headers: {}, body: { hits: { total: { value: 120 } } }, records: Math.min(50, 120 - Number(req.body?.from)) });
    }
    expect(froms).toEqual([0, 50, 100]);
  });
  it("none: one call", () => {
    expect(drive(createPaginator({ type: "none" }), () => ({ body: {}, records: 3 }))).toHaveLength(1);
  });
});
