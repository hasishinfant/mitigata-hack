import { describe, expect, it } from "vitest";
import { createPaginator, parseLinkHeader } from "../src/engine/paginate/index.ts";

const base = new URL("https://api.example.test/items?x=1");

/** Drive a paginator against a fake provider; returns the URLs fetched. */
function drive(p: ReturnType<typeof createPaginator>, respond: (u: URL) => { headers?: Record<string, string>; body: unknown; records: number }) {
  const fetched: string[] = [];
  let url: URL | null = p.start(base);
  while (url && fetched.length < 50) {
    fetched.push(url.href);
    const r = respond(url);
    url = p.next({ url, headers: r.headers ?? {}, body: r.body, records: r.records });
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
  it("none: one call", () => {
    expect(drive(createPaginator({ type: "none" }), () => ({ body: {}, records: 3 }))).toHaveLength(1);
  });
});
