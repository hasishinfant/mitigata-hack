// API process: health, records, runs, quarantine, config validation/registration, "run now",
// and the static dashboard. Holds no secrets and makes no outbound calls.
// Reads are open on loopback; every state-changing route needs `Authorization: Bearer $IX_ADMIN_TOKEN`.
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import type { PgBoss } from "pg-boss";
import type pg from "pg";
import { validateConfigText } from "../config/validate.ts";
import { enqueueRun } from "../scheduler/queue.ts";
import { ConnectorConfigError, registerConnector } from "../store/connectors.ts";
import { getHealth } from "../store/health.ts";
import { listQuarantine } from "../store/quarantine.ts";
import { ENTITY_ALIASES, queryRecords } from "../store/query.ts";
import { listRuns } from "../store/runs.ts";

const PUBLIC = join(import.meta.dirname, "public");
const STATIC: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
  "/style.css": { file: "style.css", type: "text/css; charset=utf-8" },
};
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

export type ApiOptions = { pool: pg.Pool; boss?: PgBoss; adminToken?: string; env?: Record<string, string | undefined> };

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

  app.setErrorHandler((err: Error & { statusCode?: number }, _req, reply) => {
    if (err instanceof ConnectorConfigError) return reply.code(422).send({ error: err.message, errors: err.issues });
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

  app.post("/v1/configs/validate", async (req) => {
    const res = validateConfigText(yamlBody(req), { env });
    return { ok: res.ok, errors: res.errors, warnings: res.warnings, config_hash: res.configHash };
  });

  // ---- writes (admin token) ----
  app.post("/v1/connectors", { preHandler: requireAdmin }, async (req, reply) => {
    const r = await registerConnector(opts.pool, yamlBody(req), { env, mustNotExist: true, createdBy: "api" });
    return reply.code(201).send(r);
  });

  app.put("/v1/connectors/:id", { preHandler: requireAdmin }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const text = yamlBody(req);
    const v = validateConfigText(text, { env });
    if (v.config && v.config.metadata.id !== id) return reply.code(400).send({ error: `metadata.id is ${v.config.metadata.id}, URL says ${id}` });
    return registerConnector(opts.pool, text, { env, mustExist: true, createdBy: "api" });
  });

  app.post("/v1/connectors/:id/runs", { preHandler: requireAdmin }, async (req, reply) => {
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
