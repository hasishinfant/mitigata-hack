// Data integrity of a run, without a database: a scripted provider and an in-memory run store.
//   - a 200 with the wrong envelope is a failure, never "0 records, success";
//   - pagination that stops without proof of the last page (cycle, repeated page, missing total) is a failure;
//   - the incremental watermark only moves for complete, non-degraded runs, and never past a quarantined record.
import { describe, expect, it } from "vitest";
import { BrokerError, type Broker, type BrokerRequest } from "../src/broker/types.ts";
import { resolveConnector, type ResolvedConnector } from "../src/config/load.ts";
import { validateConfigText } from "../src/config/validate.ts";
import { extractRecords, runStream, RunFailure, type Checkpoint, type FieldStats, type FinishRun, type PageCommit, type RunStore } from "../src/engine/runner.ts";

type Reply = { status?: number; body: unknown; headers?: Record<string, string> };

function connector(stream: string): ResolvedConnector {
  const yaml = `apiVersion: ix/v1
kind: Connector
metadata: { id: t-conn, source: test, tenant: demo }
connection: { base_url: "https://api.example.test", auth: { type: none } }
streams:
${stream}
policy: { allowed_hosts: [api.example.test], max_requests_per_run: 20 }
`;
  const v = validateConfigText(yaml, { env: {} });
  if (!v.ok || !v.config) throw new Error(JSON.stringify(v.errors));
  return resolveConnector(v.config, v.configHash);
}

function fakeBroker(respond: (url: URL, n: number) => Reply) {
  const calls: URL[] = [];
  const broker: Broker = {
    async request(req: BrokerRequest) {
      const url = new URL(req.url);
      calls.push(url);
      const r = respond(url, calls.length);
      return { status: r.status ?? 200, headers: r.headers ?? {}, body: r.body === "" ? "" : JSON.stringify(r.body), durationMs: 1, retries: 0, rateLimitedMs: 0 };
    },
    async credentialInfo() {
      return {};
    },
  };
  return { broker, calls };
}

function memStore() {
  const s = { watermark: undefined as string | undefined, checkpoint: null as Checkpoint | null, pages: [] as PageCommit[], runs: [] as FinishRun[], alerts: [] as { kind: string; message: string }[] };
  const store: RunStore = {
    async startRun() {},
    async commitPage(p) {
      s.pages.push(p);
      s.checkpoint = p.checkpoint;
    },
    async finishRun(r) {
      s.runs.push(r);
      if (r.watermark) s.watermark = r.watermark; // same contract as Postgres: status and watermark together
      return { status: r.status, ...(r.lastError !== undefined ? { lastError: r.lastError } : {}), watermarkSaved: Boolean(r.watermark) };
    },
    async loadCheckpoint() {
      if (!s.checkpoint && !s.watermark) return null;
      return { ...(s.checkpoint ?? { configHash: "" }), ...(s.watermark ? { cursorValue: s.watermark } : {}) };
    },
    async previousFieldStats(): Promise<FieldStats | null> {
      return [...s.runs].reverse().find((r) => r.status === "success" || r.status === "partial")?.fieldStats ?? null;
    },
    async connectorState() {
      return { status: "enabled", pausedUntil: null, reason: null };
    },
    async recentStatuses() {
      return s.runs.map((r) => r.status).reverse();
    },
    async pause() {},
    async resume() {},
    async raiseAlert(_c, kind, message) {
      s.alerts.push({ kind, message });
    },
  };
  return { s, store };
}

const run = (conn: ResolvedConnector, broker: Broker, store: RunStore) => runStream({ connector: conn, stream: conn.streams[0]!, broker, store });

describe("response envelope", () => {
  const fails = (body: unknown, path?: string) => expect(() => extractRecords(body, path)).toThrow(RunFailure);
  it("a missing records key, an empty body or an error object is a failure", () => {
    fails({ message: "Service is under maintenance" }, "vulnerabilities[*]");
    fails({ vulnerabilities: { a: 1 } }, "vulnerabilities[*]");
    fails({ message: "x" }, "data");
    fails(null, "$");
    fails(null, undefined);
    fails({ errorCode: "E0000011" }, "$");
    expect(() => extractRecords({ message: "x" }, "data")).toThrow(/records_path "data" not found.*response keys: message/);
  });
  it("a present envelope with no records is a valid empty page", () => {
    expect(extractRecords({ vulnerabilities: [] }, "vulnerabilities[*]")).toEqual([]);
    expect(extractRecords({ data: null }, "data")).toEqual([]);
    expect(extractRecords([], "$")).toEqual([]);
    expect(extractRecords({ hits: { hits: [{ a: 1 }] } }, "hits.hits[*]")).toEqual([{ a: 1 }]);
  });
  it("run: a maintenance page on page 2 fails the run; no success with partial data", async () => {
    const conn = connector(`  - name: cves
    entity: event
    request: { method: GET, path: /cves }
    records_path: "vulnerabilities[*]"
    pagination: { type: offset, offset_param: start, limit_param: n, limit: 2, total_path: total }
    mapping:
      id: { path: id, required: true }
      type: { const: vulnerability }`);
    const { broker } = fakeBroker((u) =>
      u.searchParams.get("start") === "0" ? { body: { total: 4, vulnerabilities: [{ id: "a" }, { id: "b" }] } } : { body: { message: "Service is under maintenance" } },
    );
    const { s, store } = memStore();
    const r = await run(conn, broker, store);
    expect(r.status).toBe("failed");
    expect(r.lastError).toMatch(/envelope invalid.*vulnerabilities/);
    expect(s.checkpoint?.nextUrl).toContain("start=2"); // resumes at the page that broke
  });
});

describe("pagination termination", () => {
  const cursorConn = () =>
    connector(`  - name: items
    entity: event
    request: { method: GET, path: /items }
    records_path: items
    pagination: { type: cursor, token_path: next, token_param: c }
    mapping:
      id: { path: id, required: true }
      type: { const: x }`);

  it("a cursor cycle A -> B -> A is detected: failed, position cleared", async () => {
    const next: Record<string, string> = { "": "A", A: "B", B: "A" };
    const { broker, calls } = fakeBroker((u) => {
      const c = u.searchParams.get("c") ?? "";
      return { body: { items: [{ id: `${c}-1` }], next: next[c] } };
    });
    const { s, store } = memStore();
    const r = await run(cursorConn(), broker, store);
    expect(r.status).toBe("failed");
    expect(r.lastError).toMatch(/pagination cycle/);
    expect(calls).toHaveLength(3);
    expect(s.checkpoint).toBeNull();
  });

  it("a repeated cursor is a failure, not a completed run", async () => {
    const { broker } = fakeBroker(() => ({ body: { items: [{ id: "x" }], next: "same" } }));
    const r = await run(cursorConn(), broker, memStore().store);
    expect(r.status).toBe("failed");
    expect(r.lastError).toMatch(/same cursor/);
  });

  it("a provider that ignores the page parameter is caught on the second page", async () => {
    const conn = connector(`  - name: items
    entity: event
    request: { method: GET, path: /items }
    records_path: $
    pagination: { type: page_number, page_param: page, size_param: size, size: 2 }
    mapping:
      id: { path: id, required: true }
      type: { const: x }`);
    const { broker, calls } = fakeBroker(() => ({ body: [{ id: "1" }, { id: "2" }] }));
    const r = await run(conn, broker, memStore().store);
    expect(r.status).toBe("failed");
    expect(r.lastError).toMatch(/page 2 has the same content as page 1/);
    expect(calls).toHaveLength(2); // not 20 identical requests up to max_requests_per_run
  });

  it("a missing total_path is a failure", async () => {
    const conn = connector(`  - name: items
    entity: event
    request: { method: GET, path: /items }
    records_path: items
    pagination: { type: offset, offset_param: start, limit_param: n, limit: 2, total_path: total }
    mapping:
      id: { path: id, required: true }
      type: { const: x }`);
    const { broker } = fakeBroker(() => ({ body: { items: [{ id: "1" }, { id: "2" }] } }));
    const r = await run(conn, broker, memStore().store);
    expect(r).toMatchObject({ status: "failed", lastError: expect.stringMatching(/total_path "total" missing/) });
  });

  it("a natural end still completes", async () => {
    const { broker } = fakeBroker((u) => (u.searchParams.get("c") ? { body: { items: [{ id: "2" }] } } : { body: { items: [{ id: "1" }], next: "A" } }));
    expect((await run(cursorConn(), broker, memStore().store)).status).toBe("success");
  });
});

describe("incremental watermark", () => {
  const incConn = () =>
    connector(`  - name: logs
    entity: event
    request: { method: GET, path: /logs }
    records_path: $
    pagination: { type: none }
    incremental: { cursor_field: published, param: since, template: "{{cursor}}" }
    mapping:
      id: { path: uuid, required: true }
      type: { path: eventType, required: true }
      timestamp: { path: published, transform: to_iso8601 }
      description: { path: msg }
    expect: { max_quarantine_ratio: 1 }`); // these tests are about the watermark; publication limits are tested in staging tests
  const ev = (n: number, extra: Record<string, unknown> = {}) => ({ uuid: `u${n}`, eventType: "login", published: `2026-01-0${n}T00:00:00.000Z`, msg: "m", ...extra });

  it("a clean run advances to the newest accepted record", async () => {
    const { broker } = fakeBroker(() => ({ body: [ev(1), ev(3), ev(2)] }));
    const { s, store } = memStore();
    const r = await run(incConn(), broker, store);
    expect(r.status).toBe("success");
    expect(s.watermark).toBe("2026-01-03T00:00:00.000Z");
  });

  it("a run with quarantined records keeps the previous watermark; the window is replayed", async () => {
    let body: unknown[] = [ev(1)];
    const { broker, calls } = fakeBroker(() => ({ body }));
    const { s, store } = memStore();
    await run(incConn(), broker, store);
    expect(s.watermark).toBe("2026-01-01T00:00:00.000Z");

    const bad = ev(2, { eventType: undefined }); // no type -> quarantined
    body = [bad, ev(3)];
    const r1 = await run(incConn(), broker, store);
    expect(r1.status).toBe("partial");
    expect(s.watermark).toBe("2026-01-01T00:00:00.000Z"); // unchanged, even though ev(3) was accepted
    expect(r1.lastError).toMatch(/watermark held: 1 record\(s\) quarantined/);

    body = [{ ...bad, eventType: "login" }, ev(3)]; // provider (or mapping) fixed
    const r2 = await run(incConn(), broker, store);
    expect(calls[2]!.searchParams.get("since")).toBe("2026-01-01T00:00:00.000Z"); // same window as the bad run
    expect(r2).toMatchObject({ status: "success", recordsOk: 2 });
    expect(s.watermark).toBe("2026-01-03T00:00:00.000Z");
  });

  it("holds the watermark whatever the quarantined record's cursor looks like", async () => {
    const { broker } = fakeBroker(() => ({ body: [ev(1), { uuid: "u9", eventType: "login", published: "not a date" }, { uuid: "u8" }] }));
    const { s, store } = memStore();
    const r = await run(incConn(), broker, store);
    expect(r.status).toBe("partial");
    expect(s.watermark).toBeUndefined();
    expect(r.watermarkHeld).toMatch(/2 record\(s\) quarantined/);
  });

  it("a degraded (schema drift) run does not advance the watermark", async () => {
    const day = (d: number, withMsg: boolean) => Array.from({ length: 6 }, (_, i) => ({ uuid: `d${d}-${i}`, eventType: "login", published: `2026-02-0${d}T0${i}:00:00.000Z`, ...(withMsg ? { msg: "m" } : {}) }));
    let body = day(1, true);
    const { broker } = fakeBroker(() => ({ body }));
    const { s, store } = memStore();
    expect((await run(incConn(), broker, store)).status).toBe("success");
    const before = s.watermark;
    body = day(2, false); // provider dropped the field the mapping reads
    const r = await run(incConn(), broker, store);
    expect(r.status).toBe("degraded");
    expect(s.watermark).toBe(before);
    expect(r.watermarkHeld).toMatch(/degraded/);
  });

  // Paged incremental stream: cursor pagination, newest record on the last page.
  const pagedConn = (maxRequests = 20) => {
    const c = connector(`  - name: logs
    entity: event
    request: { method: GET, path: /logs }
    records_path: items
    pagination: { type: cursor, token_path: next, token_param: c }
    incremental: { cursor_field: published, param: since, template: "{{cursor}}" }
    mapping:
      id: { path: uuid, required: true }
      type: { path: eventType, required: true }`);
    c.runtime.maxRequestsPerRun = maxRequests;
    return c;
  };
  const page = (n: number, next?: string): Reply => ({ body: { items: [ev(n)], ...(next ? { next } : {}) } });
  const seeded = () => {
    const m = memStore();
    m.s.watermark = "2025-12-31T00:00:00.000Z";
    return m;
  };

  it("pagination anomaly: watermark held", async () => {
    const { broker } = fakeBroker((u) => (u.searchParams.get("c") ? page(2, "A") : page(1, "A"))); // A -> A
    const { s, store } = seeded();
    const r = await run(pagedConn(), broker, store);
    expect(r.status).toBe("failed");
    expect(r.lastError).toMatch(/same cursor/);
    expect(s.watermark).toBe("2025-12-31T00:00:00.000Z");
  });

  it("max_requests_per_run reached: watermark held (next run continues from the checkpoint)", async () => {
    const { broker } = fakeBroker((u) => {
      const c = Number(u.searchParams.get("c") ?? 0);
      return page((c % 8) + 1, String(c + 1)); // endless, distinct pages
    });
    const { s, store } = seeded();
    const r = await run(pagedConn(3), broker, store);
    expect(r).toMatchObject({ status: "partial", lastError: expect.stringMatching(/max_requests_per_run \(3\)/) });
    expect(s.watermark).toBe("2025-12-31T00:00:00.000Z");
    expect(s.checkpoint?.nextUrl).toContain("c=3");
  });

  it("worker interruption mid-run (network gone, or a crash while committing): watermark held; the resumed run advances it", async () => {
    let down = true;
    const { broker } = fakeBroker((u) => {
      const c = u.searchParams.get("c");
      if (c === "B" && down) throw new BrokerError("network", "network error: ECONNRESET");
      return c === "B" ? page(3) : c === "A" ? page(2, "B") : page(1, "A");
    });
    const { s, store } = seeded();
    const r1 = await run(pagedConn(), broker, store);
    expect(r1.status).toBe("failed");
    expect(s.watermark).toBe("2025-12-31T00:00:00.000Z"); // pages 1-2 committed, watermark untouched
    down = false;
    const r2 = await run(pagedConn(), broker, store);
    expect(r2).toMatchObject({ status: "success", resumed: true });
    expect(s.watermark).toBe("2026-01-03T00:00:00.000Z");

    // A crash inside the page commit (process dies / DB gone) never reaches the watermark step either.
    const m = seeded();
    const crashing: RunStore = { ...m.store, commitPage: async (p) => (p.checkpoint === null ? Promise.reject(new Error("connection terminated")) : m.store.commitPage(p)) };
    const { broker: b2 } = fakeBroker((u) => (u.searchParams.get("c") ? page(5) : page(4, "A")));
    expect((await run(pagedConn(), b2, crashing)).status).toBe("failed");
    expect(m.s.watermark).toBe("2025-12-31T00:00:00.000Z");
  });

  it("a failed run (wrong envelope) does not advance the watermark", async () => {
    const { broker } = fakeBroker(() => ({ body: { not: "an array" } }));
    const { s, store } = memStore();
    expect((await run(incConn(), broker, store)).status).toBe("failed");
    expect(s.watermark).toBeUndefined();
  });
});

describe("detection rules: our credential used from outside the hub", () => {
  it("records matching the rule from IPs outside allowed_ips raise foreign_ip_use and land in the receipt", async () => {
    const conn = connector(`  - name: logs
    entity: event
    request: { method: GET, path: /logs }
    records_path: $
    pagination: { type: none }
    detect:
      - name: hub client used from outside the hub
        match: { "actor.alternateId": client-1, eventType: token.grant }
        ip_path: client.ipAddress
        allowed_ips: ["198.51.100.10, 10.0.0.0/8"]
    mapping:
      id: { path: uuid, required: true }
      type: { path: eventType, required: true }`);
    const ev = (uuid: string, actor: string, ip: string, type = "token.grant") => ({ uuid, eventType: type, actor: { alternateId: actor }, client: { ipAddress: ip } });
    const { broker } = fakeBroker(() => ({
      body: [
        ev("e1", "client-1", "198.51.100.10"), // the hub itself
        ev("e2", "client-1", "10.1.2.3"), // inside a declared range
        ev("e3", "client-1", "203.0.113.7"), // stolen token, attacker's IP
        ev("e4", "client-1", "203.0.113.7"),
        ev("e5", "someone-else", "203.0.113.7"), // other actors are not our credential
        ev("e6", "client-1", "203.0.113.8", "user.login"), // not the event type the rule is about
      ],
    }));
    const { s, store } = memStore();
    const r = await run(conn, broker, store);
    expect(r.status).toBe("success");
    expect(r.detections).toEqual([{ rule: "hub client used from outside the hub", hits: 2, ips: { "203.0.113.7": 2 }, sample_ids: ["e3", "e4"] }]);
    expect(s.alerts).toEqual([{ kind: "foreign_ip_use", message: 'logs: "hub client used from outside the hub": 2 event(s) from outside the allowed IPs: 203.0.113.7 (2); e.g. e3, e4' }]);
    const receipt = s.runs.at(-1)!.publication!.receipt as { detections: unknown[] };
    expect(receipt.detections).toEqual(r.detections);
  });
});
