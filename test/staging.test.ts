// T7 + T8 against the real test database: staged ingestion, the integrity decision, controlled promotion, receipts.
// Nothing reaches the common tables until a sync is verified; held syncs wait for an operator; rejected ones are
// discarded; every run leaves a receipt whose digest is recomputable.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { Broker } from "../src/broker/types.ts";
import { receiptDigest } from "../src/engine/receipt.ts";
import { runConnector } from "../src/engine/runner.ts";
import { createPool, type Pool } from "../src/store/db.ts";
import { loadActiveConnector, registerConnector } from "../src/store/connectors.ts";
import { closeRunLocks } from "../src/store/runLock.ts";
import { createPgRunStore } from "../src/store/runs.ts";
import { resolveHeldSync, verifyReceipt } from "../src/store/staging.ts";
import { buildApi } from "../src/api/server.ts";
import { clearData, hasDb, regPool, testUrl } from "./helpers/db.ts";

const yaml = (id: string) => `apiVersion: ix/v1
kind: Connector
metadata: { id: ${id}, source: stg, tenant: demo }
connection: { base_url: "http://localhost:1", auth: { type: none } }
streams:
  - name: items
    entity: event
    request: { method: GET, path: /items }
    records_path: items
    pagination: { type: cursor, token_path: next, token_param: c }
    mapping:
      id: { path: id, required: true }
      type: { path: kind, required: true }
      description: { path: msg }
policy: { allowed_hosts: [localhost], max_requests_per_run: 20 }
`;
type Page = { items: unknown[]; next?: string };
const item = (id: string, extra: Record<string, unknown> = {}) => ({ id, kind: "alert", msg: "m", ...extra });
/** Provider stub: pages by cursor ("" = first page). */
const provider = (pages: Record<string, Page>): Broker => ({
  async request(req) {
    const c = new URL(req.url).searchParams.get("c") ?? "";
    const p = pages[c];
    if (!p) throw new Error(`no page for cursor ${c}`);
    return { status: 200, headers: {}, body: JSON.stringify(p), durationMs: 1, retries: 0, rateLimitedMs: 0 };
  },
  async credentialInfo() {
    return {};
  },
});

describe.skipIf(!hasDb)("staged ingestion and integrity receipts", () => {
  let pool: Pool;
  const count = async (sql: string, v: unknown[] = []) => Number((await pool.query(sql, v)).rows[0].count);
  const published = (id: string) => count("select count(*) from events where connector_id = $1", [id]);
  const staged = (id: string) => count("select count(*) from stage_records r join stage_syncs s using (sync_id) where s.connector_id = $1", [id]);
  const receipts = async (id: string) =>
    (await pool.query("select id, sync_id, decision, published, body, digest from sync_receipts where connector_id = $1 order by id", [id])).rows;
  const run = async (id: string, b: Broker) => (await runConnector({ connector: await loadActiveConnector(pool, id, {}), broker: b, store: createPgRunStore(pool) }))[0]!;
  const register = (id: string, edit: (y: string) => string = (y) => y) => registerConnector(regPool(), edit(yaml(id)), { env: {} });
  const cap = (n: number) => (y: string) => y.replace("max_requests_per_run: 20", `max_requests_per_run: ${n}`);

  beforeAll(() => {
    pool = createPool(testUrl("DATABASE_URL_APP"));
  });
  afterAll(async () => {
    await closeRunLocks(pool);
    await pool?.end();
  });
  beforeEach(async () => {
    await clearData(pool);
  });

  it("verified: published in one step at the end, with a receipt whose digest is recomputable", async () => {
    await register("stg-ok");
    const r = await run("stg-ok", provider({ "": { items: [item("a"), item("b")], next: "2" }, "2": { items: [item("c")] } }));
    expect(r).toMatchObject({ status: "success", decision: "verified", published: 3 });
    expect(await published("stg-ok")).toBe(3);
    expect(await staged("stg-ok")).toBe(0);
    const [rc] = await receipts("stg-ok");
    expect(rc).toMatchObject({ decision: "verified", published: true });
    expect(receiptDigest(rc.body)).toBe(rc.digest);
    expect(rc.body).toMatchObject({
      counts: { sync: { pages: 2, seen: 3, accepted: 3, quarantined: 0 } },
      pagination: { completed: true, termination: "provider signalled the last page" },
      records_published: 3, published: true, connector: { id: "stg-ok", config_version: 1 },
    });
    expect(rc.body.pages).toHaveLength(2);
    expect(rc.body.pages[0]).toMatchObject({ n: 1, status: 200, records: 2, body_sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(rc.body.inferences[0]).toMatch(/inferred from the provider's last-page signal/);
    expect(rc.body.not_claimed).toContain("that the provider's data is true");
    expect(await verifyReceipt(pool, Number(rc.id))).toEqual({ id: Number(rc.id), digestMatches: true, anchored: false, anchorMatches: null });
  });

  it("pagination anomaly: rejected; nothing published and the staged pages are discarded", async () => {
    await register("stg-loop");
    const r = await run("stg-loop", provider({ "": { items: [item("a")], next: "A" }, A: { items: [item("b")], next: "A" } }));
    expect(r).toMatchObject({ status: "failed", decision: "rejected" });
    expect(await published("stg-loop")).toBe(0);
    expect(await staged("stg-loop")).toBe(0);
    expect((await receipts("stg-loop")).map((x) => [x.decision, x.published])).toEqual([["rejected", false]]);
  });

  it("an interrupted sync is incomplete: no partial data visible; the resumed run publishes the whole sync once", async () => {
    await register("stg-cap", cap(2));
    const pages = { "": { items: [item("a")], next: "2" }, "2": { items: [item("b")], next: "3" }, "3": { items: [item("c")], next: "4" }, "4": { items: [item("d")] } };
    const r1 = await run("stg-cap", provider(pages));
    expect(r1).toMatchObject({ status: "partial", decision: "incomplete" });
    expect(await published("stg-cap")).toBe(0); // two pages fetched, none visible
    expect(await staged("stg-cap")).toBe(2);
    const r2 = await run("stg-cap", provider(pages));
    expect(r2).toMatchObject({ status: "success", decision: "verified", resumed: true, published: 4, syncId: r1.syncId });
    expect(await published("stg-cap")).toBe(4);
    const rs = await receipts("stg-cap");
    expect(rs.map((x) => x.decision)).toEqual(["incomplete", "verified"]);
    expect(rs[1].body.counts.sync).toEqual({ pages: 4, seen: 4, accepted: 4, quarantined: 0 }); // totals across both runs
  });

  it("too much quarantine: held for review, nothing published; approve publishes and leaves its own receipt", async () => {
    await register("stg-q");
    const r = await run("stg-q", provider({ "": { items: [item("a"), { id: "b" }, { id: "c" }] } })); // 2 of 3 lack `kind`
    expect(r).toMatchObject({ status: "degraded", decision: "held", lastError: expect.stringMatching(/held for review: 2 of 3 records quarantined \(67% > 10% allowed\)/) });
    expect(await published("stg-q")).toBe(0);
    expect(await count("select count(*) from stage_syncs where connector_id = 'stg-q' and state = 'held'")).toBe(1);

    const done = await resolveHeldSync(pool, r.syncId!, "approve", "tester");
    expect(done).toMatchObject({ records: 1, connectorId: "stg-q" });
    expect(await published("stg-q")).toBe(1);
    expect(await staged("stg-q")).toBe(0);
    const rs = await receipts("stg-q");
    expect(rs.map((x) => [x.decision, x.published])).toEqual([["held", false], ["approved", true]]);
    expect(rs[1].body.prior_receipts).toEqual([{ id: rs[0].id, digest: rs[0].digest }]);
    await expect(resolveHeldSync(pool, r.syncId!, "approve", "tester")).rejects.toThrow(/not held/);
  });

  it("approving an old held sync after newer data was published is refused (no silent rollback)", async () => {
    await register("stg-old");
    const held = await run("stg-old", provider({ "": { items: [item("a", { msg: "old" }), { id: "x" }, { id: "y" }] } }));
    expect(held.decision).toBe("held");
    const fresh = await run("stg-old", provider({ "": { items: [item("a", { msg: "new" })] } }));
    expect(fresh).toMatchObject({ decision: "verified", published: 1 });
    await expect(resolveHeldSync(pool, held.syncId!, "approve", "tester")).rejects.toThrow(/newer sync .* was published since/);
    expect((await pool.query("select description from events where source_id = 'a'")).rows[0].description).toBe("new");
    expect(await resolveHeldSync(pool, held.syncId!, "discard", "tester")).toMatchObject({ records: 1 });
    expect((await receipts("stg-old")).map((x) => x.decision)).toEqual(["held", "verified", "discarded"]);
  });

  it("a field the mapping reads changes type: held as a schema change (fingerprint diff), even with no missing values", async () => {
    await register("stg-schema");
    expect((await run("stg-schema", provider({ "": { items: [item("a")] } }))).decision).toBe("verified"); // baseline: msg is a string
    const r = await run("stg-schema", provider({ "": { items: [item("b", { msg: 42 })] } }));
    expect(r).toMatchObject({ decision: "held", lastError: expect.stringMatching(/schema change: description: \/msg changed type string -> number/) });
    expect(await published("stg-schema")).toBe(1); // only the first sync
    const rs = await receipts("stg-schema");
    expect(rs[1].body.schema.breaking).toEqual(["description: /msg changed type string -> number"]);
    expect(rs[0].body.schema.fingerprint).not.toBe(rs[1].body.schema.fingerprint);
  });

  it("a legitimately empty result is verified_empty; too few records against expect.min_records is held", async () => {
    await register("stg-empty");
    expect(await run("stg-empty", provider({ "": { items: [] } }))).toMatchObject({ status: "success", decision: "verified_empty", published: 0 });
    await register("stg-min", (y) => y.replace("      description: { path: msg }\n", "      description: { path: msg }\n    expect: { min_records: 2 }\n"));
    const r = await run("stg-min", provider({ "": { items: [item("a")] } }));
    expect(r).toMatchObject({ decision: "held", lastError: expect.stringMatching(/1 records accepted, expected at least 2/) });
    expect(await published("stg-min")).toBe(0);
  });

  it("a new sync discards older open staging of the same stream, but never a held one", async () => {
    await register("stg-gc", cap(1));
    const pages = { "": { items: [item("a")], next: "2" }, "2": { items: [item("b")] } };
    expect((await run("stg-gc", provider(pages))).decision).toBe("incomplete"); // sync 1 open, 1 page staged
    await pool.query("update checkpoints set page_state = page_state || '{\"config_hash\": \"other\"}'::jsonb"); // position no longer resumable
    expect((await run("stg-gc", provider(pages))).decision).toBe("incomplete"); // sync 2 starts over and drops sync 1
    expect(await count("select count(*) from stage_syncs where connector_id = 'stg-gc'")).toBe(1);
  });

  it("API: receipts list and verification, held syncs, approve needs the admin token; health shows the decision", async () => {
    await register("stg-api");
    const r = await run("stg-api", provider({ "": { items: [item("a"), { id: "b" }, { id: "c" }] } })); // held
    const app = buildApi({ pool, env: {}, adminToken: "admin-token-for-test-123456" });
    const list = (await app.inject({ url: "/v1/connectors/stg-api/receipts" })).json().receipts;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ decision: "held", published: false, sync_counts: { seen: 3, quarantined: 2 } });
    const one = (await app.inject({ url: `/v1/receipts/${list[0].id}` })).json();
    expect(one.verification).toMatchObject({ digestMatches: true, anchored: false });
    expect(one.receipt.body.reasons[0]).toMatch(/2 of 3 records quarantined/);
    expect((await app.inject({ url: "/v1/held?connector=stg-api" })).json().held).toEqual([expect.objectContaining({ sync_id: r.syncId, records: 1 })]);

    const health = (await app.inject({ url: "/v1/health" })).json().connectors.find((c: { id: string }) => c.id === "stg-api");
    expect(health.integrity).toMatchObject({ held: 1, streams: [expect.objectContaining({ stream: "items", decision: "held", published: false })] });

    expect((await app.inject({ method: "POST", url: `/v1/syncs/${r.syncId}/approve` })).statusCode).toBe(401);
    const ok = await app.inject({ method: "POST", url: `/v1/syncs/${r.syncId}/approve`, headers: { authorization: "Bearer admin-token-for-test-123456" } });
    expect(ok.json()).toMatchObject({ action: "approve", records: 1 });
    expect(await published("stg-api")).toBe(1);
    expect((await app.inject({ method: "POST", url: `/v1/syncs/${r.syncId}/approve`, headers: { authorization: "Bearer admin-token-for-test-123456" } })).statusCode).toBe(404);
    const page = (await app.inject({ url: "/" })).body;
    expect(page).toContain('id="receipts"');
    expect(page).toContain('id="caps"');
    const caps = (await app.inject({ url: "/v1/capabilities" })).json();
    expect(caps.connectors.find((c: { id: string }) => c.id === "stg-api").capabilities).toMatchObject({ staged_integrity: { status: "enforced" }, token_binding: { status: "not_applicable" } });
  });
});
