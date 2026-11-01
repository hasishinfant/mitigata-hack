// Broker process API, served on two Unix sockets (mode 0600: only this OS user can connect).
//   request socket (IX_BROKER_SOCKET): what workers and the scheduler need, and nothing else:
//     provider calls for already-signed connectors, credential info, cache drops, alert delivery.
//   admin socket (IX_BROKER_ADMIN_SOCKET): registration and signing, secrets, removal, panic, ledger.
//     Every call needs the x-ix-broker-admin header (IX_BROKER_ADMIN_TOKEN, held by the API and CLI only).
// So a compromised worker cannot get a config signed, and cannot point a stored secret at a new host.
// The broker is the only process with the master key and the broker DB role. It:
//   - executes provider requests for registered, broker-signed connectors only;
//   - accepts secrets write-only (there is no route that returns a secret value);
//   - registers and signs config versions;
//   - appends every outbound call, denial, secret write and registration to the audit ledger.
import { timingSafeEqual } from "node:crypto";
import { chmod, stat, unlink } from "node:fs/promises";
import { connect } from "node:net";
import Fastify from "fastify";
import type pg from "pg";
import type { ResolvedConnector } from "../config/load.ts";
import { resolveConnector } from "../config/load.ts";
import { validateConfigText } from "../config/validate.ts";
import { testConnection } from "../engine/testConnection.ts";
import { log } from "../log.ts";
import { credentialRefs } from "../config/load.ts";
import { ConnectorConfigError, loadSignedConnector, registerConnector, setConnectorEnabled } from "../store/connectors.ts";
import { createLocalBroker, type LocalBroker } from "./client.ts";
import { httpCall } from "./http.ts";
import { ADMIN_HEADER } from "./remote.ts";
import { hostAllowed } from "./policy.ts";
import { configSigKey, signConfig, verifyConfigSig } from "./configSig.ts";
import { appendLedger, verifyLedger } from "./ledger.ts";
import { receiptDigest } from "../engine/receipt.ts";
import { DenialLog } from "./limits.ts";
import { canaryKey, containsCanary, makeCanary, makeCanaryUrl } from "./canary.ts";
import { advisorPrompt, type Assessment } from "../security/advisor.ts";
import { claudeNarrative } from "../advisor/claude.ts";
import { GROQ_BASE_URL, groqNarrative } from "../advisor/groq.ts";
import type { Clock } from "./retry.ts";
import { chainSecretSources, dbSecretSource, deleteSecret, envSecretSource, listSecrets, putSecret, unseal } from "./secrets.ts";
import { BrokerError, type BrokerRequest, type SecretSource } from "./types.ts";

const CONFIG_TTL_MS = 2000;
const NOTIFY_LOCK = 74_201_107; // advisory lock: alert deliveries are serialised so throttle counts are exact // a disable or re-registration takes effect within 2 s
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
  /** Token required on every admin-socket call. Without it the admin routes are disabled (503). */
  adminToken?: string;
  /** Alert delivery throttle (request socket): per connector and overall, per window. */
  notifyLimit?: { perConnector: number; total: number; windowMs: number };
  /** Window for summarising repeated denials in the ledger (default 60 s). */
  denialWindowMs?: number;
  now?: () => number;
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
  const rawSecrets: SecretSource = opts.envSecrets ? chainSecretSources(store, envSecretSource(env)) : store;
  // Canary guard: every secret the broker is about to USE is checked. A decoy is never used; using one is an alarm.
  const ckey = canaryKey(opts.masterKey);
  const canaryAlert = async (message: string) => {
    await opts.pool.query("insert into alerts (connector_id, kind, message) values (null, 'canary_triggered', $1)", [message.slice(0, 1000)]);
  };
  const secrets: SecretSource = {
    async get(tenant, ref) {
      const v = await rawSecrets.get(tenant, ref);
      if (v && containsCanary(ckey, v)) {
        const msg = `decoy credential ${tenant}/${ref} was about to be used inside the hub: a config or request references a canary. Treat the credential store as exposed.`;
        await denials.record(`canary:${tenant}/${ref}`, { action: "canary", path: `${tenant}/${ref}`, decision: `deny: ${msg}` });
        await canaryAlert(msg);
        throw new BrokerError("policy_denied", `secret "${ref}" is a decoy credential; refusing to use it (security alert raised)`);
      }
      return v;
    },
  };
  /** Decrypt every stored secret and keep the decoys (no last_used_at update: listing is not use). */
  const canaries = async (tenant?: string) => {
    const rows = (
      await opts.pool.query("select tenant_id, ref, ciphertext, wrapped_dek, nonce, created_at from credentials where ($1::text is null or tenant_id = $1) order by tenant_id, ref", [tenant ?? null])
    ).rows;
    const out: { tenant: string; ref: string; kind: "url" | "key"; value: string; created_at: string }[] = [];
    for (const r of rows) {
      const value = unseal(opts.masterKey, r.tenant_id, r.ref, { ciphertext: r.ciphertext, wrappedDek: r.wrapped_dek, nonce: r.nonce });
      if (containsCanary(ckey, value)) out.push({ tenant: r.tenant_id, ref: r.ref, kind: /^https?:\/\//.test(value) ? "url" : "key", value, created_at: r.created_at });
    }
    return out;
  };
  const audit = async (e: Parameters<typeof appendLedger>[1]): Promise<void> => void (await appendLedger(opts.pool, e));

  const cache = new Map<string, { conn: ResolvedConnector; at: number }>();
  const lastHash = new Map<string, string>(); // config hash each connector's cached token was minted under
  async function getConnector(id: string): Promise<ResolvedConnector | undefined> {
    const hit = cache.get(id);
    if (hit && Date.now() - hit.at < CONFIG_TTL_MS) return hit.conn;
    try {
      const conn = await loadSignedConnector(opts.pool, id, (cid, v, h, sig) => verifyConfigSig(sigKey, cid, v, h, sig), env);
      // A new approved version (scopes, token URL) must not reuse a token minted for the old one. The broker
      // notices this itself, so workers need no way to flush its caches.
      const prev = lastHash.get(id);
      if (prev && prev !== conn.configHash) broker.forget(id);
      lastHash.set(id, conn.configHash);
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
  /** Connector-scoped: its token, its config cache and its own secret values. Global: everything. */
  const forget = (id?: string) => {
    if (id) {
      const conn = cache.get(id)?.conn;
      broker.forget(id);
      cache.delete(id);
      if (conn) store.forget(conn.metadata.tenant, [...credentialRefs(conn), ...(conn.alerts?.slack_webhook_ref ? [conn.alerts.slack_webhook_ref] : [])]);
      return;
    }
    broker.forget();
    store.forget();
    cache.clear();
  };

  const now = opts.now ?? Date.now;
  const denials = new DenialLog(audit, opts.denialWindowMs ?? 60_000, now);
  const nl = opts.notifyLimit ?? { perConnector: 10, total: 60, windowMs: 10 * 60_000 };


  const makeApp = () => {
    const a = Fastify({ logger: false, bodyLimit: 2 * 1024 * 1024 });
    a.setErrorHandler((err: Error & { statusCode?: number }, _req, reply) => {
      if (err instanceof BrokerError)
        return reply.code(err.kind === "policy_denied" ? 403 : 502).send({ error: { kind: err.kind, message: err.message, retries: err.retries, rateLimitedMs: err.rateLimitedMs } });
      if (err instanceof ConnectorConfigError) return reply.code(422).send({ error: { kind: "invalid_config", message: err.message, issues: err.issues } });
      const code = err.statusCode && err.statusCode < 500 ? err.statusCode : 500;
      if (code === 500) log.error({ err: err.message }, "broker internal error");
      return reply.code(code).send({ error: { kind: "error", message: code === 500 ? "internal broker error" : err.message } });
    });
    a.get("/v1/ping", async () => ({ ok: true }));
    return a;
  };

  // ---- request socket: workers and scheduler ----
  const app = makeApp();

  app.post("/v1/request", async (req) => broker.request(req.body as BrokerRequest));

  app.get("/v1/credential-info/:id", async (req) => broker.credentialInfo((req.params as { id: string }).id));

  // Anchor a Sync Integrity Receipt: the broker reads the stored receipt itself, recomputes its digest from the body,
  // and appends it to the hash-chained ledger once. The caller only names the receipt; it can't supply the digest.
  // Later edits to the receipt no longer match its anchor (ix receipt verify). Evidence, not proof of upstream truth.
  app.post("/v1/receipts/:id/anchor", async (req) => {
    const id = Number((req.params as { id: string }).id);
    if (!Number.isSafeInteger(id) || id <= 0) throw Object.assign(new Error("bad receipt id"), { statusCode: 400 });
    const r = (await opts.pool.query("select id, connector_id, stream, decision, body, digest, anchored_seq from sync_receipts where id = $1", [id])).rows[0];
    if (!r) throw Object.assign(new Error(`receipt ${id} not found`), { statusCode: 404 });
    if (r.anchored_seq) throw Object.assign(new Error(`receipt ${id} is already anchored (ledger #${r.anchored_seq})`), { statusCode: 409 });
    const digest = receiptDigest(r.body);
    if (digest !== r.digest) {
      await audit({ connectorId: r.connector_id, action: "receipt", path: r.stream, decision: `deny: receipt #${id} body does not match its digest` });
      throw Object.assign(new Error(`receipt ${id} was changed after it was written`), { statusCode: 409 });
    }
    const seq = await appendLedger(opts.pool, { connectorId: r.connector_id, action: "receipt", path: r.stream, decision: `${r.decision} receipt #${id} sha256:${digest}` });
    await opts.pool.query("update sync_receipts set anchored_seq = $2 where id = $1 and anchored_seq is null", [id, seq]);
    return { seq };
  });

  // ---- admin socket: API and CLI, with the admin token ----
  const adminApp = makeApp();
  const want = opts.adminToken ? Buffer.from(opts.adminToken) : undefined;
  adminApp.addHook("onRequest", async (req, reply) => {
    if (req.url === "/v1/ping") return;
    if (!want) return reply.code(503).send({ error: { kind: "error", message: "broker admin routes are disabled: set IX_BROKER_ADMIN_TOKEN" } });
    const h = req.headers[ADMIN_HEADER];
    const got = Buffer.from(typeof h === "string" ? h : "");
    if (got.length !== want.length || !timingSafeEqual(got, want)) {
      // Bounded: one row per window plus a summary count, not one serialized ledger write per bad request.
      await denials.record("admin-token", { action: "admin", path: req.url.split("?")[0] ?? null, decision: "deny: bad or missing broker admin token" });
      return reply.code(401).send({ error: { kind: "error", message: "broker admin token required" } });
    }
  });
  adminApp.addHook("onClose", async () => denials.close());

  // Cache invalidation is admin-only: from a worker it would be a lever to force token re-minting
  // and secret re-reads. Without connectorId: everything (used after panic, secret changes, tests).
  adminApp.post("/v1/forget", async (req) => {
    const id = (req.body as { connectorId?: unknown } | undefined)?.connectorId;
    if (id !== undefined && typeof id !== "string") throw Object.assign(new Error("connectorId must be a string"), { statusCode: 400 });
    forget(id);
    return { ok: true, scope: id ? "connector" : "all" };
  });

  adminApp.post("/v1/connectors", async (req) => {
    const { yaml, mode, createdBy, confirmHosts } = req.body as { yaml: string; mode: "add" | "update"; createdBy?: string; confirmHosts?: boolean };
    if (typeof yaml !== "string") throw Object.assign(new Error("yaml is required"), { statusCode: 400 });
    const r = await registerConnector(opts.pool, yaml, {
      env, createdBy: createdBy ?? "broker", mustNotExist: mode === "add", mustExist: mode === "update",
      sign: (id, version, hash) => signConfig(sigKey, id, version, hash),
      confirmHosts: confirmHosts === true,
    });
    forget(r.id);
    await audit({
      connectorId: r.id, action: "register",
      decision:
        `${r.changed ? `allow: v${r.version}` : `allow: v${r.version} unchanged`}` +
        `${r.firstBinding?.length ? `; first binding of stored secret(s) ${r.firstBinding.join(", ")}` : ""}` +
        `${r.newHosts?.length ? `; secrets now also sent to ${r.newHosts.join(", ")} (confirmed)` : ""}`,
    });
    return r;
  });

  // Secret refs a stored config uses (auth credentials and the alert webhook).
  const refsOf = (yaml: string): string[] => {
    const res = validateConfigText(yaml, { env });
    if (!res.config) return [];
    const c = resolveConnector(res.config, res.configHash);
    return [...credentialRefs(c), ...(c.alerts?.slack_webhook_ref ? [c.alerts.slack_webhook_ref] : [])];
  };

  // Remove a connector: its config versions, runs, checkpoints, quarantine, alerts and every record it
  // stored. With purge_secrets, also delete its secrets, except refs another connector still uses.
  adminApp.delete("/v1/connectors/:id", async (req) => {
    const { id } = req.params as { id: string };
    const purge = (req.query as { purge_secrets?: string }).purge_secrets === "1";
    const client = await opts.pool.connect();
    let records = 0;
    const secrets = { deleted: [] as string[], kept_shared: [] as string[] };
    try {
      await client.query("begin");
      const found = await client.query("select 1 from connectors where id = $1 for update", [id]);
      if (!found.rowCount) {
        await client.query("rollback");
        throw Object.assign(new Error(`connector ${id} not found`), { statusCode: 404 });
      }
      if (purge) {
        const all = (
          await client.query(
            `select k.id, k.tenant_id, v.config_yaml from connectors k
             join connector_versions v on v.connector_id = k.id and v.version = k.active_version`,
          )
        ).rows as { id: string; tenant_id: string; config_yaml: string }[];
        const mine = all.find((r) => r.id === id);
        const usedElsewhere = new Set(all.filter((r) => r.id !== id && r.tenant_id === mine?.tenant_id).flatMap((r) => refsOf(r.config_yaml)));
        for (const ref of new Set(mine ? refsOf(mine.config_yaml) : [])) {
          if (usedElsewhere.has(ref)) secrets.kept_shared.push(ref);
          else if ((await client.query("delete from credentials where tenant_id = $1 and ref = $2", [mine!.tenant_id, ref])).rowCount) secrets.deleted.push(ref);
        }
      }
      for (const t of ["users", "devices", "events"]) records += (await client.query(`delete from ${t} where connector_id = $1`, [id])).rowCount ?? 0;
      await client.query("delete from quarantine where connector_id = $1", [id]);
      await client.query("delete from sync_receipts where connector_id = $1", [id]); // staging cascades with the connector
      await client.query("delete from alerts where connector_id = $1", [id]);
      await client.query("delete from connectors where id = $1", [id]); // cascades versions, runs, checkpoints
      await client.query("commit");
    } catch (e) {
      await client.query("rollback").catch(() => {});
      throw e;
    } finally {
      client.release();
    }
    forget(id);
    if (purge) forget(); // drop cached secret values too
    await audit({ connectorId: id, action: "remove", decision: `allow: ${records} records deleted${purge ? `, ${secrets.deleted.length} secrets deleted` : ""}` });
    return { removed: true, records, ...(purge ? { secrets } : {}) };
  });

  // Re-enabling is broker-only (the app role can disable, never re-enable): undoing a kill switch is an admin act.
  adminApp.post("/v1/connectors/:id/enable", async (req) => {
    const { id } = req.params as { id: string };
    if (!(await setConnectorEnabled(opts.pool, id, true))) throw Object.assign(new Error(`connector ${id} not found`), { statusCode: 404 });
    forget(id);
    await audit({ connectorId: id, action: "enable", decision: "allow" });
    return { id, status: "enabled" };
  });

  // ---- incident advisor: the broker holds the Claude API key and builds the prompt itself ----
  // (callers send the rule-based assessment, never a prompt, so this can't be used as a general Claude proxy)
  adminApp.post("/v1/advisor/narrate", async (req) => {
    const a = (req.body as { assessment?: Assessment } | undefined)?.assessment;
    if (!a || !Array.isArray(a.findings) || !Array.isArray(a.evidence)) throw Object.assign(new Error("assessment is required"), { statusCode: 400 });
    const tenant = env.IX_ADVISOR_TENANT || "demo";
    const apiKey = await secrets.get(tenant, "anthropic_api_key");
    if (!apiKey) {
      // No Claude key: use Groq if its key is stored.
      const groqKey = await secrets.get(tenant, "groq_api_key");
      if (!groqKey) throw Object.assign(new Error(`no AI key: ix secret set anthropic_api_key (or groq_api_key) (tenant ${tenant})`), { statusCode: 409 });
      const gBase = env.IX_ADVISOR_GROQ_BASE_URL || GROQ_BASE_URL;
      const gHost = new URL(gBase).host;
      const { system, user } = advisorPrompt(a);
      try {
        const r = await groqNarrative({ apiKey: groqKey, baseURL: gBase, model: env.IX_ADVISOR_GROQ_MODEL, system, user });
        await audit({ action: "advisor", method: "POST", host: gHost, path: "/chat/completions", decision: r.refusal ? `error: refusal (${r.refusal})` : "allow" });
        return r;
      } catch (e) {
        await audit({ action: "advisor", method: "POST", host: gHost, path: "/chat/completions", decision: `error: ${(e as Error).name}` });
        throw Object.assign(new Error(`Groq call failed: ${(e as Error).message.slice(0, 200)}`), { statusCode: 502 });
      }
    }
    const baseURL = env.IX_ADVISOR_BASE_URL || undefined;
    const host = baseURL ? new URL(baseURL).host : "api.anthropic.com";
    const { system, user } = advisorPrompt(a);
    try {
      const r = await claudeNarrative({ apiKey, ...(baseURL ? { baseURL } : {}), system, user });
      await audit({ action: "advisor", method: "POST", host, path: "/v1/messages", decision: r.refusal ? `error: refusal (${r.refusal})` : "allow" });
      return r;
    } catch (e) {
      await audit({ action: "advisor", method: "POST", host, path: "/v1/messages", decision: `error: ${(e as Error).name}` });
      throw Object.assign(new Error(`Claude call failed: ${(e as Error).message.slice(0, 200)}`), { statusCode: 502 });
    }
  });

  // ---- credential canaries ----
  adminApp.post("/v1/canaries", async (req) => {
    const { tenant = "demo", ref, kind = "key", prefix = "" } = (req.body ?? {}) as { tenant?: string; ref?: string; kind?: string; prefix?: string };
    if (!TENANT_RE.test(tenant) || typeof ref !== "string" || !REF_RE.test(ref)) throw Object.assign(new Error("bad tenant or ref"), { statusCode: 400 });
    if (kind !== "key" && kind !== "url") throw Object.assign(new Error('kind must be "key" or "url"'), { statusCode: 400 });
    if (!/^[A-Za-z0-9_]{0,12}$/.test(prefix)) throw Object.assign(new Error("prefix: up to 12 letters, digits or _"), { statusCode: 400 });
    if ((await opts.pool.query("select 1 from credentials where tenant_id = $1 and ref = $2", [tenant, ref])).rowCount)
      throw Object.assign(new Error(`secret ${tenant}/${ref} already exists; a canary never replaces a real secret`), { statusCode: 409 });
    const base = env.IX_CANARY_BASE_URL || `http://localhost:${env.IX_API_PORT || 7070}`;
    const value = kind === "url" ? makeCanaryUrl(ckey, base) : makeCanary(ckey, prefix);
    await putSecret(opts.pool, opts.masterKey, tenant, ref, value);
    await audit({ action: "canary_create", path: `${tenant}/${ref}`, decision: `allow: ${kind} decoy` });
    // The value is a decoy, so returning it is safe: the operator may plant copies (fake .env files, docs, tickets).
    return { tenant, ref, kind, value };
  });
  adminApp.get("/v1/canaries", async (req) =>
    ({ canaries: (await canaries((req.query as { tenant?: string }).tenant)).map(({ value: _v, ...c }) => c) }));
  // The API's canary listener forwards anything that looks like a token; only the broker can tell a decoy.
  adminApp.post("/v1/canaries/check", async (req) => {
    const { text = "", ip = null, ua = null } = (req.body ?? {}) as { text?: string; ip?: string | null; ua?: string | null };
    if (!containsCanary(ckey, String(text))) return { canary: false };
    const hit = (await canaries()).find((c) => String(text).includes(c.kind === "url" ? c.value.split("/").pop()! : c.value));
    const what = hit ? `${hit.tenant}/${hit.ref}` : "an unknown decoy";
    const msg = `decoy credential ${what} was USED OUTSIDE the hub, from ${ip ?? "unknown IP"}${ua ? ` (${String(ua).slice(0, 120)})` : ""}. Someone has a copy of the credential store or a planted file.`;
    await denials.record(`canary-hit:${what}`, { action: "canary", path: what, host: ip ? String(ip).slice(0, 64) : null, decision: `deny: ${msg}` });
    await canaryAlert(msg);
    return { canary: true, ref: hit?.ref ?? null };
  });

  adminApp.put("/v1/secrets/:tenant/:ref", async (req) => {
    const { tenant, ref } = req.params as { tenant: string; ref: string };
    const value = (req.body as { value?: unknown } | undefined)?.value;
    if (!TENANT_RE.test(tenant) || !REF_RE.test(ref)) throw Object.assign(new Error("bad tenant or ref"), { statusCode: 400 });
    if (typeof value !== "string" || value === "") throw Object.assign(new Error("value must be a non-empty string"), { statusCode: 400 });
    await putSecret(opts.pool, opts.masterKey, tenant, ref, value);
    forget(); // any connector using this ref gets a fresh token
    await audit({ action: "secret_set", path: `${tenant}/${ref}`, decision: "allow" });
    return { ok: true, tenant, ref, chars: value.length };
  });

  adminApp.get("/v1/secrets", async (req) => ({ secrets: await listSecrets(opts.pool, (req.query as { tenant?: string }).tenant) }));

  adminApp.delete("/v1/secrets/:tenant/:ref", async (req) => {
    const { tenant, ref } = req.params as { tenant: string; ref: string };
    const deleted = await deleteSecret(opts.pool, tenant, ref);
    forget();
    await audit({ action: "secret_delete", path: `${tenant}/${ref}`, decision: deleted ? "allow" : "allow: not found" });
    return { deleted };
  });

  // Testing an unregistered file is only safe when it uses no secrets: otherwise an ad-hoc config could
  // point a stored secret at any host. Configs with auth must be registered (and signed) first.
  adminApp.post("/v1/test-inline", async (req) => {
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

  adminApp.get("/v1/ledger/verify", async () => verifyLedger(opts.pool));

  // Panic: revoke every cached OAuth token that has a revocation endpoint, wipe all in-memory tokens and
  // config caches, and optionally delete every stored secret. Connectors are disabled by the caller (app DB);
  // the broker then refuses their calls on the next request.
  adminApp.post("/v1/panic", async (req) => {
    const { purgeSecrets, actor } = (req.body ?? {}) as { purgeSecrets?: boolean; actor?: string };
    const revocations = await broker.revokeAll();
    forget();
    let purged = 0;
    if (purgeSecrets) purged = (await opts.pool.query("delete from credentials")).rowCount ?? 0;
    await audit({ actor: actor ?? "panic", action: "panic", decision: `allow: ${revocations.filter((r) => r.revoked).length} revoked, ${purged} secrets purged` });
    return { revocations, purged };
  });

  // Alert delivery (request socket: the scheduler needs it). The webhook URL is a secret (it embeds a token), so only
  // the broker sends it, only to an allowed host, and the ledger records the host but never the path.
  // The caller names an alert row, not a message: the broker reads the row, builds the text itself, and marks it
  // delivered in the same transaction that holds the row lock. Delivery is AT LEAST ONCE: concurrent or repeated calls
  // for a delivered row are refused, but if the webhook accepts the message and the broker then crashes or loses the
  // database before committing, the row is still pending and is sent again (Slack webhooks take no idempotency key).
  // The throttle counts deliveries recorded in the alerts table, so it survives a broker restart. Over the limit the
  // alert stays pending and the scheduler retries later.
  // Limits: the broker does not check where an alert row came from. The app role can insert rows, so a compromised
  // worker can queue forged alerts; the throttle bounds the send rate, not the queue, and forged rows ahead of real
  // ones in the queue use up the throttle first.
  const throttled = async (connectorId: string | null, scope: string) => {
    await denials.record(connectorId ? `notify:${connectorId}` : "notify:all", { connectorId, action: "alert", decision: `deny: alert rate limit (${scope})` });
    return Object.assign(new Error(`alert rate limit reached (${scope}); try again later`), { statusCode: 429 });
  };
  app.post("/v1/notify", async (req) => {
    const alertId = Number((req.body as { alertId?: unknown } | undefined)?.alertId);
    if (!Number.isSafeInteger(alertId) || alertId <= 0) throw Object.assign(new Error("alertId is required"), { statusCode: 400 });
    const client = await opts.pool.connect();
    try {
      await client.query("begin");
      await client.query("select pg_advisory_xact_lock($1)", [NOTIFY_LOCK]); // one delivery at a time: exact throttle counts
      const row = (await client.query("select id, connector_id, kind, message, delivered from alerts where id = $1 for update", [alertId])).rows[0] as
        | { id: number; connector_id: string | null; kind: string; message: string; delivered: boolean }
        | undefined;
      if (!row) throw Object.assign(new Error(`alert ${alertId} not found`), { statusCode: 404 });
      if (row.delivered) throw Object.assign(new Error(`alert ${alertId} was already delivered`), { statusCode: 409 });
      const done = async (delivered: boolean, channel: string, detail: string) => {
        await client.query("update alerts set delivered = $2, channel = $3, delivered_at = case when $2 then now() end where id = $1", [alertId, delivered || channel === "none", channel]);
        await client.query("commit");
        return { delivered, channel, detail };
      };
      if (!row.connector_id) return await done(false, "none", "alert has no connector");
      const sent = (
        await client.query(
          `select count(*)::int as total, count(*) filter (where connector_id = $1)::int as mine from alerts
           where channel = 'slack' and delivered and delivered_at > now() - make_interval(secs => $2)`,
          [row.connector_id, nl.windowMs / 1000],
        )
      ).rows[0] as { total: number; mine: number };
      if (sent.total >= nl.total) throw await throttled(null, "all connectors");
      if (sent.mine >= nl.perConnector) throw await throttled(row.connector_id, "per connector");

      let conn: ResolvedConnector;
      try {
        conn = await loadSignedConnector(opts.pool, row.connector_id, (cid, v, h, sig) => verifyConfigSig(sigKey, cid, v, h, sig), env);
      } catch (e) {
        throw new BrokerError("policy_denied", (e as Error).message);
      }
      const connectorId = conn.metadata.id;
      const ref = conn.alerts?.slack_webhook_ref;
      if (!ref) return await done(false, "none", "connector has no alerts.slack_webhook_ref");
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
      const text = `:rotating_light: [IntegrateX] ${connectorId} · ${row.kind}: ${row.message}`.slice(0, 3000);
      const res = await httpCall("POST", url, { "content-type": "application/json", "user-agent": "IntegrateX/0.1" }, { timeoutMs: 10_000, maxBytes: 64 * 1024, body: JSON.stringify({ text }) });
      await audit({ connectorId, action: "alert", method: "POST", host: url.host, path: "[webhook]", status: res.status, decision: res.status < 300 ? "allow" : `error: HTTP ${res.status}` });
      const ok = res.status >= 200 && res.status < 300;
      if (!ok) throw Object.assign(new Error(`webhook answered HTTP ${res.status}`), { statusCode: 502 });
      return await done(true, "slack", `HTTP ${res.status}`);
    } catch (e) {
      await client.query("rollback").catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  });

  return { app, adminApp, broker, forget };
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
