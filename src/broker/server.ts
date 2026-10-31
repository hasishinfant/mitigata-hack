// Broker process API, served on a Unix socket (mode 0600: only this OS user can connect).
// The broker is the only process with the master key and the broker DB role. It:
//   - executes provider requests for registered, broker-signed connectors only;
//   - accepts secrets write-only (there is no route that returns a secret value);
//   - registers and signs config versions;
//   - appends every outbound call, denial, secret write and registration to the audit ledger.
import { chmod, stat, unlink } from "node:fs/promises";
import { connect } from "node:net";
import Fastify from "fastify";
import type pg from "pg";
import type { ResolvedConnector } from "../config/load.ts";
import { resolveConnector } from "../config/load.ts";
import { validateConfigText } from "../config/validate.ts";
import { testConnection } from "../engine/testConnection.ts";
import { log } from "../log.ts";
import { ConnectorConfigError, loadSignedConnector, registerConnector } from "../store/connectors.ts";
import { createLocalBroker, type LocalBroker } from "./client.ts";
import { httpCall } from "./http.ts";
import { hostAllowed } from "./policy.ts";
import { configSigKey, signConfig, verifyConfigSig } from "./configSig.ts";
import { appendLedger, verifyLedger } from "./ledger.ts";
import type { Clock } from "./retry.ts";
import { chainSecretSources, dbSecretSource, deleteSecret, envSecretSource, listSecrets, putSecret } from "./secrets.ts";
import { BrokerError, type BrokerRequest, type SecretSource } from "./types.ts";

const CONFIG_TTL_MS = 2000; // a disable or re-registration takes effect within 2 s
const REF_RE = /^[a-z][a-z0-9_]{1,63}$/;
const TENANT_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

export type BrokerServerOptions = {
  pool: pg.Pool; // ix_broker role
  masterKey: Buffer;
  env?: Record<string, string | undefined>;
  /** Dev/mock only: also accept IX_SECRET_<REF> from the broker's own environment. */
  envSecrets?: boolean;
  clock?: Clock;
  random?: () => number;
  /** Hosts alert webhooks may point at (IX_ALERT_WEBHOOK_HOSTS, default hooks.slack.com). */
  alertHosts?: string[];
};

/** The credential ref that identifies a connector's credential (where learned scopes are recorded). */
export function primaryRef(conn: ResolvedConnector): string | undefined {
  const a = conn.connection.auth;
  switch (a.type) {
    case "api_key":
    case "bearer":
      return a.secret_ref;
    case "basic":
      return a.password_ref;
    case "oauth2_client_credentials":
      return a.client_id_ref;
    default:
      return undefined;
  }
}

export function createBrokerServer(opts: BrokerServerOptions) {
  const env = opts.env ?? process.env;
  const sigKey = configSigKey(opts.masterKey);
  const store = dbSecretSource(opts.pool, opts.masterKey);
  const secrets: SecretSource = opts.envSecrets ? chainSecretSources(store, envSecretSource(env)) : store;
  const audit = (e: Parameters<typeof appendLedger>[1]) => appendLedger(opts.pool, e);

  const cache = new Map<string, { conn: ResolvedConnector; at: number }>();
  async function getConnector(id: string): Promise<ResolvedConnector | undefined> {
    const hit = cache.get(id);
    if (hit && Date.now() - hit.at < CONFIG_TTL_MS) return hit.conn;
    try {
      const conn = await loadSignedConnector(opts.pool, id, (cid, v, h, sig) => verifyConfigSig(sigKey, cid, v, h, sig), env);
      cache.set(id, { conn, at: Date.now() });
      return conn;
    } catch (e) {
      cache.delete(id);
      await audit({ connectorId: id, action: "request", decision: `deny: ${(e as Error).message}` });
      throw new BrokerError("policy_denied", (e as Error).message);
    }
  }

  // Record what the provider says the credential can do, so posture cards can flag over-privileged tokens.
  const onScopes = async (conn: ResolvedConnector, scopes: string[]) => {
    const ref = primaryRef(conn);
    if (!ref) return;
    const a = conn.connection.auth;
    const revocable = conn.credential?.revocable_by_api ?? (a.type === "oauth2_client_credentials" && Boolean(a.revocation_url));
    await opts.pool.query(
      "update credentials set granted_scopes = $3, scopes_seen_at = now(), revocable_by_api = $4 where tenant_id = $1 and ref = $2",
      [conn.metadata.tenant, ref, scopes, revocable],
    );
  };
  const alertHosts = opts.alertHosts ?? (env.IX_ALERT_WEBHOOK_HOSTS ?? "hooks.slack.com").split(",").map((h) => h.trim()).filter(Boolean);

  const broker: LocalBroker = createLocalBroker({ getConnector, secrets, audit, onScopes, clock: opts.clock, random: opts.random });
  const forget = (id?: string) => {
    broker.forget(id);
    store.forget();
    if (id) cache.delete(id);
    else cache.clear();
  };

  const app = Fastify({ logger: false, bodyLimit: 2 * 1024 * 1024 });
  app.setErrorHandler((err: Error & { statusCode?: number }, _req, reply) => {
    if (err instanceof BrokerError)
      return reply.code(err.kind === "policy_denied" ? 403 : 502).send({ error: { kind: err.kind, message: err.message, retries: err.retries, rateLimitedMs: err.rateLimitedMs } });
    if (err instanceof ConnectorConfigError) return reply.code(422).send({ error: { kind: "invalid_config", message: err.message, issues: err.issues } });
    const code = err.statusCode && err.statusCode < 500 ? err.statusCode : 500;
    if (code === 500) log.error({ err: err.message }, "broker internal error");
    return reply.code(code).send({ error: { kind: "error", message: code === 500 ? "internal broker error" : err.message } });
  });

  app.get("/v1/ping", async () => ({ ok: true }));

  app.post("/v1/request", async (req) => broker.request(req.body as BrokerRequest));

  app.get("/v1/credential-info/:id", async (req) => broker.credentialInfo((req.params as { id: string }).id));

  app.post("/v1/forget", async (req) => {
    forget((req.body as { connectorId?: string } | undefined)?.connectorId);
    return { ok: true };
  });

  app.post("/v1/connectors", async (req) => {
    const { yaml, mode, createdBy } = req.body as { yaml: string; mode: "add" | "update"; createdBy?: string };
    if (typeof yaml !== "string") throw Object.assign(new Error("yaml is required"), { statusCode: 400 });
    const r = await registerConnector(opts.pool, yaml, {
      env, createdBy: createdBy ?? "broker", mustNotExist: mode === "add", mustExist: mode === "update",
      sign: (id, version, hash) => signConfig(sigKey, id, version, hash),
    });
    forget(r.id);
    await audit({ connectorId: r.id, action: "register", decision: r.changed ? `allow: v${r.version}` : `allow: v${r.version} unchanged` });
    return r;
  });

  app.put("/v1/secrets/:tenant/:ref", async (req) => {
    const { tenant, ref } = req.params as { tenant: string; ref: string };
    const value = (req.body as { value?: unknown } | undefined)?.value;
    if (!TENANT_RE.test(tenant) || !REF_RE.test(ref)) throw Object.assign(new Error("bad tenant or ref"), { statusCode: 400 });
    if (typeof value !== "string" || value === "") throw Object.assign(new Error("value must be a non-empty string"), { statusCode: 400 });
    await putSecret(opts.pool, opts.masterKey, tenant, ref, value);
    forget(); // any connector using this ref gets a fresh token
    await audit({ action: "secret_set", path: `${tenant}/${ref}`, decision: "allow" });
    return { ok: true, tenant, ref, chars: value.length };
  });

  app.get("/v1/secrets", async (req) => ({ secrets: await listSecrets(opts.pool, (req.query as { tenant?: string }).tenant) }));

  app.delete("/v1/secrets/:tenant/:ref", async (req) => {
    const { tenant, ref } = req.params as { tenant: string; ref: string };
    const deleted = await deleteSecret(opts.pool, tenant, ref);
    forget();
    await audit({ action: "secret_delete", path: `${tenant}/${ref}`, decision: deleted ? "allow" : "allow: not found" });
    return { deleted };
  });

  // Testing an unregistered file is only safe when it uses no secrets: otherwise an ad-hoc config could
  // point a stored secret at any host. Configs with auth must be registered (and signed) first.
  app.post("/v1/test-inline", async (req) => {
    const { yaml } = req.body as { yaml: string };
    const res = validateConfigText(String(yaml ?? ""), { env });
    if (!res.ok || !res.config) throw new ConnectorConfigError("config is invalid", res.errors);
    if (res.config.connection.auth.type !== "none")
      throw Object.assign(new Error("configs that use secrets must be registered first (ix add), then tested by id"), { statusCode: 409 });
    const conn = resolveConnector(res.config, res.configHash);
    const tmp = createLocalBroker({ getConnector: () => conn, secrets: { get: async () => undefined }, audit, clock: opts.clock });
    await audit({ connectorId: conn.metadata.id, action: "test", decision: "allow: inline, no secrets" });
    return testConnection(conn, tmp);
  });

  app.get("/v1/ledger/verify", async () => verifyLedger(opts.pool));

  // Panic: revoke every cached OAuth token that has a revocation endpoint, wipe all in-memory tokens and
  // config caches, and optionally delete every stored secret. Connectors are disabled by the caller (app DB);
  // the broker then refuses their calls on the next request.
  app.post("/v1/panic", async (req) => {
    const { purgeSecrets, actor } = (req.body ?? {}) as { purgeSecrets?: boolean; actor?: string };
    const revocations = await broker.revokeAll();
    forget();
    let purged = 0;
    if (purgeSecrets) purged = (await opts.pool.query("delete from credentials")).rowCount ?? 0;
    await audit({ actor: actor ?? "panic", action: "panic", decision: `allow: ${revocations.filter((r) => r.revoked).length} revoked, ${purged} secrets purged` });
    return { revocations, purged };
  });

  // Alert delivery. The webhook URL is a secret (it embeds a token), so only the broker sends it, only to an
  // allowed host, and the ledger records the host but never the path.
  app.post("/v1/notify", async (req) => {
    const { connectorId, text } = req.body as { connectorId: string; text: string };
    if (typeof text !== "string" || !text) throw Object.assign(new Error("text is required"), { statusCode: 400 });
    let conn: ResolvedConnector | undefined;
    try {
      conn = await loadSignedConnector(opts.pool, connectorId, (cid, v, h, sig) => verifyConfigSig(sigKey, cid, v, h, sig), env);
    } catch (e) {
      throw new BrokerError("policy_denied", (e as Error).message);
    }
    const ref = conn.alerts?.slack_webhook_ref;
    if (!ref) return { delivered: false, channel: "none", detail: "connector has no alerts.slack_webhook_ref" };
    const hook = await secrets.get(conn.metadata.tenant, ref);
    if (!hook) throw new BrokerError("secret_missing", `secret "${ref}" is not set (ix secret set ${ref})`);
    let url: URL;
    try {
      url = new URL(hook);
    } catch {
      throw new BrokerError("policy_denied", `secret "${ref}" is not a URL`);
    }
    const local = ["localhost", "127.0.0.1"].includes(url.hostname);
    if ((url.protocol !== "https:" && !(url.protocol === "http:" && local)) || !hostAllowed(url.hostname, alertHosts)) {
      await audit({ connectorId, action: "alert", method: "POST", host: url.host, path: "[webhook]", decision: `deny: webhook host ${url.hostname} not in IX_ALERT_WEBHOOK_HOSTS` });
      throw new BrokerError("policy_denied", `webhook host ${url.hostname} is not an allowed alert host`);
    }
    const res = await httpCall("POST", url, { "content-type": "application/json", "user-agent": "IntegrateX/0.1" }, { timeoutMs: 10_000, maxBytes: 64 * 1024, body: JSON.stringify({ text: text.slice(0, 3000) }) });
    await audit({ connectorId, action: "alert", method: "POST", host: url.host, path: "[webhook]", status: res.status, decision: res.status < 300 ? "allow" : `error: HTTP ${res.status}` });
    return { delivered: res.status >= 200 && res.status < 300, channel: "slack", detail: `HTTP ${res.status}` };
  });

  return { app, broker, forget };
}

/** Listen on a Unix socket with 0600 permissions, replacing a stale socket file if nothing is listening. */
export async function listenOnSocket(app: ReturnType<typeof Fastify>, socketPath: string): Promise<void> {
  try {
    await stat(socketPath);
    const alive = await new Promise<boolean>((resolve) => {
      const s = connect(socketPath, () => {
        s.end();
        resolve(true);
      });
      s.on("error", () => resolve(false));
    });
    if (alive) throw new Error(`another broker is already listening on ${socketPath}`);
    await unlink(socketPath);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  const oldMask = process.umask(0o177); // socket created as 0600
  try {
    await app.listen({ path: socketPath });
  } finally {
    process.umask(oldMask);
  }
  await chmod(socketPath, 0o600);
}
