// Mock provider server for local development and tests. Simulates the paging and auth styles of
// the real sources (Link header + page, offset + totalResults, Link header + opaque cursor,
// body cursor + isLast) with deterministic data. Tokens here are fake test values.
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { pathToFileURL } from "node:url";

export type MockOptions = {
  members?: number;
  cves?: number;
  directoryUsers?: number;
  tickets?: number;
  tokens?: { bearer?: string; apiKey?: string; ssws?: string; basicUser?: string; basicPass?: string };
  /** CVE indexes whose records are returned without an id (to exercise quarantine). */
  cveMissingIdAt?: number[];
  /** Simulate a provider renaming profile.email -> profile.mail (schema drift). */
  renameEmail?: boolean;
};

export type FaultMode = "429" | "500" | "503" | "timeout" | "drop" | "ratelimit403";
export type FaultSpec = {
  mode: FaultMode;
  count: number; // how many matching requests to fault
  after?: number; // let this many matching requests through first
  path?: string; // only requests whose path starts with this
  retryAfter?: string; // 429: Retry-After header value (seconds or HTTP date); omit for none
  resetInSec?: number; // ratelimit403: x-ratelimit-reset = now + this
  delayMs?: number; // timeout: how long to hang
};
export type MockCall = { method: string; path: string; query: Record<string, string> };
export type Mock = {
  app: FastifyInstance;
  calls: MockCall[];
  options: Required<Omit<MockOptions, "tokens">> & { tokens: Required<NonNullable<MockOptions["tokens"]>> };
  setFault(spec: FaultSpec | null): void;
};

export const MOCK_TOKENS = {
  bearer: "mock-bearer-token-1234",
  apiKey: "mock-api-key-5678",
  ssws: "mock-ssws-token-9012",
  basicUser: "mock@example.com",
  basicPass: "mock-basic-pass-3456",
};

const iso = (dayOffset: number) => new Date(Date.UTC(2026, 0, 1) + dayOffset * 3_600_000).toISOString();
const qp = (req: FastifyRequest) => req.query as Record<string, string>;
const origin = (req: FastifyRequest) => `${req.protocol}://${req.headers.host}`;
const intParam = (v: string | undefined, dflt: number, max: number) => Math.min(Math.max(Number.parseInt(v ?? "", 10) || dflt, 0), max);

function unauthorized(reply: FastifyReply, message = "Bad credentials") {
  return reply.code(401).send({ message });
}

export function buildMock(opts: MockOptions = {}): Mock {
  const options = {
    members: opts.members ?? 250,
    cves: opts.cves ?? 4500,
    directoryUsers: opts.directoryUsers ?? 450,
    tickets: opts.tickets ?? 120,
    cveMissingIdAt: opts.cveMissingIdAt ?? [],
    renameEmail: opts.renameEmail ?? false,
    tokens: { ...MOCK_TOKENS, ...opts.tokens },
  };
  const t = options.tokens;
  const calls: MockCall[] = [];
  const app = Fastify({ logger: false, forceCloseConnections: true });
  let fault: (FaultSpec & { seen: number }) | null = null;
  const setFault = (spec: FaultSpec | null) => {
    fault = spec ? { ...spec, seen: 0 } : null;
  };

  app.addHook("onRequest", async (req, reply) => {
    const u = new URL(req.url, "http://x");
    calls.push({ method: req.method, path: u.pathname, query: Object.fromEntries(u.searchParams) });
    if (!fault || u.pathname.startsWith("/__")) return;
    if (fault.path && !u.pathname.startsWith(fault.path)) return;
    if (fault.seen++ < (fault.after ?? 0)) return;
    if (fault.count <= 0) return;
    fault.count--;
    switch (fault.mode) {
      case "429":
        if (fault.retryAfter !== undefined) reply.header("retry-after", fault.retryAfter);
        return reply.code(429).send({ message: "Too Many Requests" });
      case "500":
      case "503":
        return reply.code(Number(fault.mode)).send({ message: "Service Unavailable" });
      case "ratelimit403":
        reply.header("x-ratelimit-remaining", "0").header("x-ratelimit-reset", String(Math.ceil(Date.now() / 1000) + (fault.resetInSec ?? 5)));
        return reply.code(403).send({ message: "API rate limit exceeded" });
      case "timeout":
        await new Promise((r) => setTimeout(r, fault?.delayMs ?? 5000).unref());
        return reply.code(504).send({ message: "late" });
      case "drop":
        req.raw.socket.destroy();
        return reply.hijack();
    }
  });

  // Fault control for live demos: /__fault?mode=429&count=1&retry_after=30&after=1 ; /__fault?mode=clear
  app.get("/__fault", async (req) => {
    const q = qp(req);
    if (!q.mode || q.mode === "clear") {
      setFault(null);
      return { fault: null };
    }
    setFault({
      mode: q.mode as FaultMode,
      count: Number(q.count ?? 1),
      after: q.after ? Number(q.after) : undefined,
      path: q.path,
      retryAfter: q.retry_after,
      resetInSec: q.reset_in ? Number(q.reset_in) : undefined,
      delayMs: q.delay_ms ? Number(q.delay_ms) : undefined,
    });
    return { fault };
  });
  // Schema drift toggle: /__drift?rename_email=1
  app.get("/__drift", async (req) => {
    options.renameEmail = qp(req).rename_email === "1";
    return { renameEmail: options.renameEmail };
  });

  // ---- GitHub-like: Bearer, Link header with page numbers ----
  app.get("/orgs/:org/members", async (req, reply) => {
    if (req.headers.authorization !== `Bearer ${t.bearer}`) return unauthorized(reply);
    const q = qp(req);
    const perPage = intParam(q.per_page, 30, 100) || 30;
    const page = Math.max(intParam(q.page, 1, 1e6), 1);
    const pages = Math.max(Math.ceil(options.members / perPage), 1);
    const startIdx = (page - 1) * perPage;
    const items = Array.from({ length: Math.max(0, Math.min(perPage, options.members - startIdx)) }, (_, i) => {
      const n = startIdx + i + 1;
      return { login: `dev${n}`, id: 1000 + n, type: "User", site_admin: n === 1, html_url: `https://example.test/dev${n}` };
    });
    const { org } = req.params as { org: string };
    const link = (p: number) => `<${origin(req)}/orgs/${org}/members?per_page=${perPage}&page=${p}>`;
    const links: string[] = [];
    if (page < pages) links.push(`${link(page + 1)}; rel="next"`, `${link(pages)}; rel="last"`);
    if (page > 1) links.push(`${link(1)}; rel="first"`, `${link(page - 1)}; rel="prev"`);
    if (links.length) reply.header("link", links.join(", "));
    reply.header("x-ratelimit-remaining", "4999");
    return items;
  });

  // ---- NVD-like: apiKey header, startIndex/resultsPerPage/totalResults ----
  app.get("/rest/json/cves/2.0", async (req, reply) => {
    if (req.headers.apikey !== t.apiKey) return reply.code(403).send({ message: "Invalid apiKey" });
    const q = qp(req);
    const per = intParam(q.resultsPerPage, 2000, 2000) || 2000;
    const start = intParam(q.startIndex, 0, 1e9);
    const count = Math.max(0, Math.min(per, options.cves - start));
    const vulnerabilities = Array.from({ length: count }, (_, i) => {
      const n = start + i;
      const score = (n * 7) % 101 / 10; // 0.0 .. 10.0
      const metrics =
        n % 10 === 9 ? {} : n % 5 === 4 ? { cvssMetricV2: [{ cvssData: { baseScore: score } }] } : { cvssMetricV31: [{ cvssData: { baseScore: score } }] };
      const cve: Record<string, unknown> = {
        sourceIdentifier: "cve@example.test",
        published: iso(n).replace("Z", "").slice(0, 23), // NVD style: no timezone suffix
        lastModified: iso(n + 1).replace("Z", "").slice(0, 23),
        vulnStatus: "Analyzed",
        descriptions: [{ lang: "en", value: `Mock vulnerability number ${n}` }],
        metrics,
      };
      if (!options.cveMissingIdAt.includes(n)) cve.id = `CVE-2026-${String(10000 + n)}`;
      return { cve };
    });
    return { resultsPerPage: count, startIndex: start, totalResults: options.cves, format: "NVD_CVE", version: "2.0", timestamp: iso(0), vulnerabilities };
  });

  // ---- Okta-like: SSWS token, Link header with opaque `after` cursor ----
  const dirUsers = () =>
    Array.from({ length: options.directoryUsers }, (_, i) => ({
      id: `00u${String(i).padStart(6, "0")}`,
      status: ["ACTIVE", "ACTIVE", "SUSPENDED", "DEPROVISIONED", "PROVISIONED"][i % 5],
      lastLogin: i % 7 === 0 ? null : iso(i),
      lastUpdated: iso(i + 2),
      created: iso(-i),
      profile: {
        firstName: `First${i}`,
        lastName: `Last${i}`,
        [options.renameEmail ? "mail" : "email"]: `User${i}@Example.TEST`,
        login: `user${i}@example.test`,
      },
    }));
  app.get("/api/v1/users", async (req, reply) => {
    if (req.headers.authorization !== `SSWS ${t.ssws}`) return unauthorized(reply, "Invalid token provided");
    const q = qp(req);
    const limit = intParam(q.limit, 200, 200) || 200;
    const all = dirUsers();
    const startIdx = q.after ? all.findIndex((u) => u.id === Buffer.from(q.after!, "base64url").toString()) + 1 : 0;
    const page = all.slice(startIdx, startIdx + limit);
    const self = `<${origin(req)}/api/v1/users?limit=${limit}${q.after ? `&after=${q.after}` : ""}>; rel="self"`;
    const last = page[page.length - 1];
    const hasMore = startIdx + limit < all.length && last;
    reply.header("link", hasMore ? `${self}, <${origin(req)}/api/v1/users?limit=${limit}&after=${Buffer.from(last.id).toString("base64url")}>; rel="next"` : self);
    return page;
  });

  // ---- Jira-like: Basic auth, body cursor nextPageToken + isLast ----
  app.get("/rest/api/3/search/jql", async (req, reply) => {
    const expected = `Basic ${Buffer.from(`${t.basicUser}:${t.basicPass}`).toString("base64")}`;
    if (req.headers.authorization !== expected) return unauthorized(reply, "Client must be authenticated");
    const q = qp(req);
    const max = intParam(q.maxResults, 50, 100) || 50;
    const startIdx = q.nextPageToken ? Number(Buffer.from(q.nextPageToken, "base64url").toString()) : 0;
    const count = Math.max(0, Math.min(max, options.tickets - startIdx));
    const issues = Array.from({ length: count }, (_, i) => {
      const n = startIdx + i;
      return {
        id: String(20000 + n),
        key: `SEC-${n + 1}`,
        fields: {
          summary: `Mock ticket ${n + 1}`,
          priority: { name: ["Lowest", "Low", "Medium", "High", "Highest"][n % 5] },
          updated: iso(n).replace("Z", "+0000"),
          status: { name: n % 3 ? "Open" : "Done" },
        },
      };
    });
    const isLast = startIdx + count >= options.tickets;
    return { issues, isLast, ...(isLast ? {} : { nextPageToken: Buffer.from(String(startIdx + count)).toString("base64url") }) };
  });

  app.get("/__health", async () => ({ ok: true }));
  return { app, calls, options, setFault };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const port = Number(process.env.MOCK_PORT ?? 4010);
  const { app } = buildMock();
  await app.listen({ host: "127.0.0.1", port });
  console.log(`mock providers on http://localhost:${port}`);
  console.log("fake credentials for: ix secret / IX_SECRET_<REF> env (test values only)");
  for (const [k, v] of Object.entries(MOCK_TOKENS)) console.log(`  ${k.padEnd(10)} ${v}`);
}
