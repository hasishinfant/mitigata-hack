// API process: health, records, runs, quarantine, config validation/registration, "run now",
// and the static dashboard. Holds no secrets and makes no outbound calls.
// Reads are open on loopback; every state-changing route needs `Authorization: Bearer $IX_ADMIN_TOKEN`.
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import type { PgBoss } from "pg-boss";
import type pg from "pg";
import type { BrokerAdmin } from "../broker/remote.ts";
import type { Broker } from "../broker/types.ts";
import { validateConfigText } from "../config/validate.ts";
import { testConnection } from "../engine/testConnection.ts";
import { enqueueRun } from "../scheduler/queue.ts";
import { panic } from "../security/panic.ts";
import { getPosture } from "../security/posture.ts";
import { ConnectorConfigError, loadActiveConnector, setConnectorEnabled } from "../store/connectors.ts";
import { getHealth } from "../store/health.ts";
import { listQuarantine } from "../store/quarantine.ts";
import { ENTITY_ALIASES, queryRecords } from "../store/query.ts";
import { listRuns } from "../store/runs.ts";
import { listHeld, listReceipts, resolveHeldSync, SyncNotHeld, verifyReceipt } from "../store/staging.ts";

const PUBLIC = join(import.meta.dirname, "public");
const STATIC: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
  "/style.css": { file: "style.css", type: "text/css; charset=utf-8" },
  "/builder.js": { file: "builder.js", type: "text/javascript; charset=utf-8" },
  "/save-flow.js": { file: "save-flow.js", type: "text/javascript; charset=utf-8" },
};
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

export type ApiOptions = {
  pool: pg.Pool; // ix_app role: cannot read credentials or write config versions
  boss?: PgBoss;
  broker?: Broker; // socket client: provider calls for "test connection"
  admin?: BrokerAdmin; // socket client: registration and write-only secrets
  adminToken?: string;
  env?: Record<string, string | undefined>;
};

export function buildApi(opts: ApiOptions) {
  const app = Fastify({ logger: false, bodyLimit: 1024 * 1024 });
  const env = opts.env ?? process.env;
  const statics = Object.fromEntries(Object.entries(STATIC).map(([route, s]) => [route, { ...s, body: readFileSync(join(PUBLIC, s.file)) }]));

  for (const type of ["text/yaml", "application/yaml", "application/x-yaml", "text/plain"])
    app.addContentTypeParser(type, { parseAs: "string" }, (_req, body, done) => done(null, body));

  app.addHook("onSend", async (_req, reply) => {
    reply.header("x-content-type-options", "nosniff").header("referrer-policy", "no-referrer").header("cache-control", "no-store");
  });

  const requireAdmin = async (req: FastifyRequest, reply: FastifyReply) => {
    if (!opts.adminToken) return reply.code(503).send({ error: "state-changing routes are disabled: set IX_ADMIN_TOKEN" });
    const got = Buffer.from((req.headers.authorization ?? "").replace(/^Bearer\s+/i, ""));
    const want = Buffer.from(opts.adminToken);
    if (got.length !== want.length || !timingSafeEqual(got, want)) return reply.code(401).send({ error: "admin token required" });
  };
  const yamlBody = (req: FastifyRequest): string => {
    const b = req.body as unknown;
    if (typeof b === "string") return b;
    if (b && typeof b === "object" && typeof (b as { yaml?: unknown }).yaml === "string") return (b as { yaml: string }).yaml;
    throw Object.assign(new Error("send the config as text/yaml, or JSON { \"yaml\": \"...\" }"), { statusCode: 400 });
  };

  const needAdmin = (): BrokerAdmin => {
    if (!opts.admin) throw Object.assign(new Error("broker not available"), { statusCode: 503 });
    return opts.admin;
  };

  app.setErrorHandler((err: Error & { statusCode?: number; issues?: unknown }, _req, reply) => {
    if (err instanceof ConnectorConfigError) return reply.code(422).send({ error: err.message, errors: err.issues });
    if (err.statusCode === 422 && err.issues) return reply.code(422).send({ error: err.message, errors: err.issues });
    const code = err.statusCode && err.statusCode < 500 ? err.statusCode : 500;
    return reply.code(code).send({ error: code === 500 ? "internal error" : err.message });
  });

  // ---- dashboard ----
  for (const [route, s] of Object.entries(statics))
    app.get(route, async (_req, reply) => reply.type(s.type).header("content-security-policy", CSP).send(s.body));

  // ---- reads ----
  app.get("/v1/health", async () => getHealth(opts.pool, env));

  app.get("/v1/connectors/:id/runs", async (req) => {
    const { id } = req.params as { id: string };
    const { limit } = req.query as { limit?: string };
    return { runs: await listRuns(opts.pool, id, Math.min(Number(limit) || 20, 200)) };
  });

  app.get("/v1/records/:entity", async (req, reply) => {
    const entity = ENTITY_ALIASES[(req.params as { entity: string }).entity];
    if (!entity) return reply.code(404).send({ error: "entity must be users, devices or events" });
    const q = req.query as Record<string, string | undefined>;
    if (q.since && Number.isNaN(Date.parse(q.since))) return reply.code(400).send({ error: "since must be an ISO date" });
    return queryRecords(opts.pool, entity, {
      source: q.source, since: q.since, type: q.type, tenant: q.tenant,
      limit: Math.min(Number(q.limit) || 50, 1000), offset: Math.max(Number(q.offset) || 0, 0), withAttributes: q.attributes === "1",
    });
  });

  app.get("/v1/quarantine", async (req) => {
    const q = req.query as { connector?: string; limit?: string };
    return { items: await listQuarantine(opts.pool, { connectorId: q.connector, limit: Math.min(Number(q.limit) || 50, 500) }) };
  });

  app.get("/v1/connectors/:id/posture", async (req) => getPosture(opts.pool, (req.params as { id: string }).id, env));

  app.get("/v1/alerts", async (req) => {
    const limit = Math.min(Number((req.query as { limit?: string }).limit) || 50, 500);
    return { alerts: (await opts.pool.query("select id, connector_id, kind, message, created_at, delivered, channel from alerts order by id desc limit $1", [limit])).rows };
  });

  // ---- canary listener ----
  // Decoy URLs point here. Anything that looks like a token is forwarded to the broker (the only process that can
  // recognise a decoy); a hit is a critical alert with the caller's IP. Always answers like a dead webhook.
  const canaryListener = async (req: FastifyRequest, reply: FastifyReply) => {
    const text = `${req.url} ${typeof req.body === "string" ? req.body.slice(0, 4096) : ""} ${String(req.headers.authorization ?? "")}`;
    if (/[A-Za-z0-9_]{40,}/.test(text)) await opts.admin?.checkCanary({ text, ip: req.ip, ua: String(req.headers["user-agent"] ?? "") }).catch(() => {});
    return reply.code(403).type("text/plain").send("invalid_token");
  };
  app.route({ method: ["GET", "POST", "PUT"], url: "/hooks/*", handler: canaryListener });

  // ---- integrity receipts and held syncs (T7/T8) ----
  app.get("/v1/connectors/:id/receipts", async (req) => {
    const limit = Math.min(Number((req.query as { limit?: string }).limit) || 20, 200);
    return { receipts: await listReceipts(opts.pool, (req.params as { id: string }).id, limit) };
  });
  app.get("/v1/receipts/:id", async (req, reply) => {
    const id = Number((req.params as { id: string }).id);
    if (!Number.isSafeInteger(id)) return reply.code(400).send({ error: "bad receipt id" });
    const r = (await opts.pool.query("select * from sync_receipts where id = $1", [id])).rows[0];
    if (!r) return reply.code(404).send({ error: `receipt ${id} not found` });
    return { receipt: r, verification: await verifyReceipt(opts.pool, id) };
  });
  app.get("/v1/held", async (req) => ({ held: await listHeld(opts.pool, (req.query as { connector?: string }).connector) }));

  app.post("/v1/configs/validate", async (req) => {
    const res = validateConfigText(yamlBody(req), { env });
    return { ok: res.ok, errors: res.errors, warnings: res.warnings, config_hash: res.configHash };
  });

  // ---- writes (admin token) ----
  // Registration goes through the broker, which validates and signs the version it will honour.
  app.post("/v1/connectors", { preHandler: requireAdmin }, async (req, reply) => {
    const confirmHosts = (req.query as { confirm_hosts?: string }).confirm_hosts === "1";
    const r = await needAdmin().register(yamlBody(req), "add", "api", { confirmHosts });
    return reply.code(201).send(r);
  });

  app.put("/v1/connectors/:id", { preHandler: requireAdmin }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const text = yamlBody(req);
    const v = validateConfigText(text, { env });
    if (v.config && v.config.metadata.id !== id) return reply.code(400).send({ error: `metadata.id is ${v.config.metadata.id}, URL says ${id}` });
    return needAdmin().register(text, "update", "api", { confirmHosts: (req.query as { confirm_hosts?: string }).confirm_hosts === "1" });
  });

  // Write-only: the value goes to the broker; nothing ever returns it.
  app.put("/v1/secrets/:ref", { preHandler: requireAdmin }, async (req) => {
    const { ref } = req.params as { ref: string };
    const tenant = (req.query as { tenant?: string }).tenant ?? "demo";
    const value = (req.body as { value?: unknown } | undefined)?.value;
    if (typeof value !== "string") throw Object.assign(new Error('send JSON { "value": "..." }'), { statusCode: 400 });
    const r = await needAdmin().putSecret(tenant, ref, value);
    return { stored: true, tenant, ref, chars: r.chars };
  });

  // Test an unregistered config. The broker allows this only for configs that use no secrets.
  app.post("/v1/configs/test", { preHandler: requireAdmin }, async (req) => needAdmin().testInline(yamlBody(req)));

  // Remove a connector and its records (through the broker; the app role cannot delete connectors).
  app.delete("/v1/connectors/:id", { preHandler: requireAdmin }, async (req) => {
    const { id } = req.params as { id: string };
    const keep = (req.query as { keep_secrets?: string }).keep_secrets === "1";
    const r = await needAdmin().removeConnector(id, { purgeSecrets: !keep });
    await opts.pool.query("delete from pgboss.job where data->>'connectorId' = $1 and state in ('created', 'retry')", [id]).catch(() => {});
    return { id, ...r };
  });

  app.post("/v1/connectors/:id/test", { preHandler: requireAdmin }, async (req, reply) => {
    if (!opts.broker) return reply.code(503).send({ error: "broker not available" });
    const conn = await loadActiveConnector(opts.pool, (req.params as { id: string }).id, env);
    return testConnection(conn, opts.broker);
  });

  app.post("/v1/connectors/:id/disable", { preHandler: requireAdmin }, async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!(await setConnectorEnabled(opts.pool, id, false, "disabled via API"))) return reply.code(404).send({ error: `connector ${id} not found` });
    await opts.admin?.forget(id).catch(() => {}); // drop its cached token now
    return { id, status: "disabled" };
  });

  app.post("/v1/connectors/:id/enable", { preHandler: requireAdmin }, async (req) => {
    const { id } = req.params as { id: string };
    return needAdmin().enableConnector(id); // broker-only: the app role cannot re-enable
  });

  // Operator decision on a held sync: publish its staged records, or discard them. Leaves its own receipt.
  for (const action of ["approve", "discard"] as const)
    app.post(`/v1/syncs/:syncId/${action}`, { preHandler: requireAdmin }, async (req, reply) => {
      const { syncId } = req.params as { syncId: string };
      if (!/^[0-9a-f-]{36}$/.test(syncId)) return reply.code(400).send({ error: "bad sync id" });
      try {
        const r = await resolveHeldSync(opts.pool, syncId, action, "api");
        await opts.broker?.anchorReceipt?.(r.receiptId).catch(() => {});
        return { sync_id: syncId, action, ...r };
      } catch (e) {
        if (e instanceof SyncNotHeld) return reply.code(404).send({ error: e.message });
        return reply.code(409).send({ error: (e as Error).message });
      }
    });

  app.post("/v1/panic", { preHandler: requireAdmin }, async (req) => {
    const body = (req.body ?? {}) as { purge_secrets?: boolean };
    return panic(opts.pool, { admin: opts.admin, boss: opts.boss, purgeSecrets: body.purge_secrets === true, actor: "api", env });
  });

  // "Run now" is low-risk (the scheduler does the same; one run per connector at a time), so the dashboard may
  // call it without the admin token. The custom header blocks cross-site requests: browsers won't send it to
  // localhost from another origin without a CORS preflight, which this API never approves.
  const requireRunAllowed = async (req: FastifyRequest, reply: FastifyReply) => {
    if (req.headers["x-ix-dashboard"] === "1") return;
    return requireAdmin(req, reply);
  };

  app.post("/v1/connectors/:id/runs", { preHandler: requireRunAllowed }, async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!opts.boss) return reply.code(503).send({ error: "job queue not available" });
    const c = (await opts.pool.query("select status from connectors where id = $1", [id])).rows[0];
    if (!c) return reply.code(404).send({ error: `connector ${id} not found` });
    if (c.status === "disabled") return reply.code(409).send({ error: `connector ${id} is disabled` });
    const jobId = await enqueueRun(opts.boss, { connectorId: id, trigger: "api" });
    return reply.code(202).send(jobId ? { queued: true, job_id: jobId } : { queued: false, reason: "a run is already queued or running" });
  });

  return app;
}
