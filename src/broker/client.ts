// In-process broker. Phase 6 moves this behind a socket in its own process;
// the Broker interface stays the same so workers don't change.
// Every outbound call gets: policy check, auth (static or OAuth2), token-bucket throttle,
// retry with backoff, 429 / Retry-After handling, and response scrubbing.
import type { ResolvedConnector } from "../config/load.ts";
import { log, registerSecretForScrub } from "../log.ts";
import { applyStaticAuth } from "./auth/index.ts";
import { OAuthTokenManager } from "./auth/oauth2.ts";
import { httpCall, type HttpResult } from "./http.ts";
import type { AuditEntry } from "./ledger.ts";
import { hostAllowed, methodAllowed, pathAllowed } from "./policy.ts";
import { backoffMs, classifyResponse, providerWaitMs, realClock, TokenBucket, type Clock } from "./retry.ts";
import {
  BrokerError, type Broker, type BrokerRequest, type BrokerResponse, type CredentialInfo, type SecretSource,
} from "./types.ts";

const MAX_BYTES = 64 * 1024 * 1024;
const MAX_RATE_LIMIT_WAITS = 5;
const FORBIDDEN_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "host", "x-api-key", "content-length", "dpop"]);

export type LocalBrokerOptions = {
  /** In the broker process this loads the broker-signed config from the database. */
  getConnector: (id: string) => ResolvedConnector | undefined | Promise<ResolvedConnector | undefined>;
  secrets: SecretSource;
  clock?: Clock;
  random?: () => number;
  /** Called for every outbound call and every denial. If it throws, the request fails (fail closed). */
  audit?: (e: AuditEntry) => Promise<void>;
  /** Called when the broker learns (or re-learns different) granted scopes for a connector's credential. */
  onScopes?: (conn: ResolvedConnector, scopes: string[], source: "token_response" | "response_header") => Promise<void>;
};

export type RevokeResult = { connectorId: string; revoked: boolean; detail: string };

export type LocalBroker = Broker & {
  /** Drop cached tokens and learned credential info (disable / panic). */
  forget(connectorId?: string): void;
  /** Panic: revoke every cached OAuth token where a revocation endpoint is configured, then drop them all. */
  revokeAll(): Promise<RevokeResult[]>;
};

type Sent = { res: HttpResult; retries: number; rateLimitedMs: number };
type Target = "api" | "token" | "revoke";

export function createLocalBroker(opts: LocalBrokerOptions): LocalBroker {
  const clock = opts.clock ?? realClock;
  const buckets = new Map<string, TokenBucket>();
  const tokens = new OAuthTokenManager();
  const headerScopes = new Map<string, string[]>();
  const reportedScopes = new Map<string, string>(); // connector -> last scopes reported via onScopes

  async function reportScopes(conn: ResolvedConnector, scopes: string[], source: "token_response" | "response_header"): Promise<void> {
    const key = [...scopes].sort().join(" ");
    if (!opts.onScopes || reportedScopes.get(conn.metadata.id) === key) return;
    reportedScopes.set(conn.metadata.id, key);
    await opts.onScopes(conn, scopes, source);
  }

  const bucketFor = (conn: ResolvedConnector): TokenBucket => {
    const rpm = conn.runtime.rateLimit.requestsPerMinute;
    let b = buckets.get(conn.metadata.id);
    if (!b || b.rpm !== rpm) buckets.set(conn.metadata.id, (b = new TokenBucket(rpm, clock.now())));
    return b;
  };

  async function auditDeny(conn: ResolvedConnector, method: string, rawUrl: string, e: unknown): Promise<void> {
    if (!opts.audit || !(e instanceof BrokerError)) return;
    let host: string | null = null;
    let path: string | null = null;
    try {
      const u = new URL(rawUrl);
      host = u.host;
      path = u.pathname;
    } catch {
      /* unparseable URL: log without host/path */
    }
    await opts.audit({ connectorId: conn.metadata.id, action: "request", method, host, path, decision: `deny: ${e.message.replace(/^policy denied: /, "")}` });
  }

  /**
   * One logical call with throttle, retries and rate-limit waits. Returns the final response.
   * headers may be a function: it is called for every attempt, so per-request values (a DPoP proof) are never reused.
   */
  async function send(
    conn: ResolvedConnector, method: string, url: URL, headers: Record<string, string> | (() => Promise<Record<string, string>>), body?: string,
  ): Promise<Sent> {
    const { retries: retryCfg, rateLimit, timeoutMs } = conn.runtime;
    const where = { connector: conn.metadata.id, method, host: url.host, path: url.pathname };
    let errorAttempts = 0; // timeouts / network errors / 5xx
    let rateWaits = 0; // 429 / quota 403
    let rateLimitedMs = 0;
    const retries = () => errorAttempts + rateWaits;

    for (;;) {
      await bucketFor(conn).take(clock);
      let res: HttpResult;
      try {
        res = await httpCall(method, url, typeof headers === "function" ? await headers() : headers, { timeoutMs, maxBytes: MAX_BYTES, body });
      } catch (e) {
        if (e instanceof BrokerError && (e.kind === "timeout" || e.kind === "network") && errorAttempts < retryCfg.max) {
          const wait = backoffMs(errorAttempts, retryCfg.baseMs, retryCfg.jitter, opts.random);
          log.warn({ ...where, error: e.kind, attempt: errorAttempts + 1, wait_ms: wait }, "retrying");
          await clock.sleep(wait, "backoff");
          errorAttempts++;
          continue;
        }
        if (e instanceof BrokerError) {
          if (errorAttempts) e.message += ` (after ${errorAttempts} retries)`;
          e.retries = retries();
          e.rateLimitedMs = rateLimitedMs;
        }
        throw e;
      }

      const cls = classifyResponse(res.status, res.headers);
      log.info({ ...where, status: res.status, attempt: retries() + 1 }, "outbound");

      if (cls === "rate_limited") {
        const asked = rateLimit.respectRetryAfter ? providerWaitMs(res.headers, clock.now()) : undefined;
        const wait = asked ?? backoffMs(rateWaits, retryCfg.baseMs, retryCfg.jitter, opts.random);
        const fail = (msg: string) => {
          const err = new BrokerError("rate_limited", msg);
          err.retries = retries();
          err.rateLimitedMs = rateLimitedMs;
          return err;
        };
        if (wait > rateLimit.maxWaitMs)
          throw fail(`provider asked to wait ${Math.ceil(wait / 1000)} s, more than max_wait ${Math.ceil(rateLimit.maxWaitMs / 1000)} s`);
        if (rateWaits >= MAX_RATE_LIMIT_WAITS) throw fail(`still rate limited after ${rateWaits} waits`);
        log.warn({ ...where, status: res.status, wait_ms: wait, source: asked === undefined ? "backoff" : "provider" }, "rate limited, waiting");
        await clock.sleep(wait, "rate_limit");
        rateLimitedMs += wait;
        rateWaits++;
        continue;
      }
      if (cls === "retryable" && errorAttempts < retryCfg.max) {
        const wait = backoffMs(errorAttempts, retryCfg.baseMs, retryCfg.jitter, opts.random);
        log.warn({ ...where, status: res.status, attempt: errorAttempts + 1, wait_ms: wait }, "retrying");
        await clock.sleep(wait, "backoff");
        errorAttempts++;
        continue;
      }
      return { res, retries: retries(), rateLimitedMs };
    }
  }

  return {
    async request(req: BrokerRequest): Promise<BrokerResponse> {
      const conn = await opts.getConnector(req.connectorId);
      if (!conn) throw new BrokerError("unknown_connector", `connector ${req.connectorId} is not registered with the broker`);
      let url: URL;
      try {
        url = checkPolicy(conn, req.method, req.url, "api");
      } catch (e) {
        await auditDeny(conn, req.method, req.url, e);
        throw e;
      }

      const headers: Record<string, string> = { "user-agent": "IntegrateX/0.1", accept: "application/json" };
      for (const [k, v] of Object.entries(req.headers ?? {})) {
        const name = k.toLowerCase();
        if (FORBIDDEN_HEADERS.has(name)) {
          const err = deny(conn, req.method, url, `header ${name} may not be set by workers`);
          await auditDeny(conn, req.method, url.href, err);
          throw err;
        }
        headers[name] = v;
      }
      let body: string | undefined;
      if (req.method === "POST") {
        body = JSON.stringify(req.body ?? {});
        headers["content-type"] = "application/json";
      }

      const auth = conn.connection.auth;
      const started = clock.now();
      let refreshed = false;
      let nonceRetried = false;
      let retries = 0;
      let rateLimitedMs = 0;
      for (;;) {
        const target = { url: new URL(url), headers: { ...headers } };
        let used: string[];
        let headersFor: Record<string, string> | (() => Promise<Record<string, string>>) = target.headers;
        let dpopToken: string | undefined;
        if (auth.type === "oauth2_client_credentials") {
          const t = await tokens.get(conn, opts.secrets, async (tokenUrl, h, b) => {
            try {
              checkPolicy(conn, "POST", tokenUrl.href, "token");
            } catch (e) {
              await auditDeny(conn, "POST", tokenUrl.href, e);
              throw e;
            }
            const r = (await send(conn, "POST", tokenUrl, h, b)).res;
            await opts.audit?.({ connectorId: conn.metadata.id, action: "token", method: "POST", host: tokenUrl.host, path: tokenUrl.pathname, status: r.status, decision: "allow" });
            return r;
          }, clock.now());
          used = t.used;
          if (t.dpop) {
            // RFC 9449: "Authorization: DPoP <token>" plus a fresh proof per attempt, bound to this token (ath).
            target.headers.authorization = `DPoP ${t.token}`;
            dpopToken = t.token;
            const base = { ...target.headers };
            headersFor = async () => ({ ...base, dpop: await tokens.dpopProof(conn.metadata.id, req.method, target.url, Date.now(), t.token) });
          } else target.headers.authorization = `Bearer ${t.token}`;
        } else {
          used = await applyStaticAuth(auth, conn.metadata.tenant, target, opts.secrets);
        }
        used.forEach(registerSecretForScrub);

        let sent: Sent;
        try {
          sent = await send(conn, req.method, target.url, headersFor, body);
        } catch (e) {
          if (e instanceof BrokerError) {
            e.retries += retries;
            e.rateLimitedMs += rateLimitedMs;
            await opts.audit?.({ connectorId: conn.metadata.id, action: "request", method: req.method, host: url.host, path: url.pathname, decision: `error: ${e.kind}` });
          }
          throw e;
        }
        await opts.audit?.({ connectorId: conn.metadata.id, action: "request", method: req.method, host: url.host, path: url.pathname, status: sent.res.status, decision: "allow" });
        retries += sent.retries;
        rateLimitedMs += sent.rateLimitedMs;

        // DPoP: the API may demand a (new) nonce. Retry once with it, same token.
        if (dpopToken && sent.res.status === 401 && /use_dpop_nonce/.test(sent.res.headers["www-authenticate"] ?? "") && !nonceRetried && tokens.learnNonce(target.url, sent.res.headers)) {
          nonceRetried = true;
          continue;
        }
        // OAuth: a 401 may mean the token was revoked or expired early. Refresh once, then give up.
        if (auth.type === "oauth2_client_credentials" && sent.res.status === 401 && !refreshed) {
          log.warn({ connector: conn.metadata.id }, "401 with cached token, refreshing once");
          tokens.invalidate(conn.metadata.id);
          refreshed = true;
          continue;
        }

        const scopesHeader = conn.credential?.scopes_header?.toLowerCase();
        const hs = scopesHeader ? sent.res.headers[scopesHeader] : undefined;
        if (hs !== undefined) {
          const list = hs.split(/[\s,]+/).filter(Boolean);
          headerScopes.set(conn.metadata.id, list);
          await reportScopes(conn, list, "response_header");
        }
        const tok = tokens.peek(conn.metadata.id);
        if (tok?.scopes) await reportScopes(conn, tok.scopes, "token_response");

        // A provider may echo a credential back (e.g. a query-string key inside a Link header). Strip it.
        return {
          status: sent.res.status,
          headers: scrubValues(sent.res.headers, used),
          body: scrubText(sent.res.body, used),
          durationMs: clock.now() - started,
          retries,
          rateLimitedMs,
        };
      }
    },

    async credentialInfo(connectorId: string): Promise<CredentialInfo> {
      const t = tokens.peek(connectorId);
      if (t?.scopes) return { grantedScopes: t.scopes, scopeSource: "token_response", tokenExpiresAt: new Date(t.expiresAt).toISOString() };
      const hs = headerScopes.get(connectorId);
      if (hs) return { grantedScopes: hs, scopeSource: "response_header" };
      return t ? { tokenExpiresAt: new Date(t.expiresAt).toISOString() } : {};
    },

    forget(connectorId?: string) {
      tokens.invalidate(connectorId);
      if (connectorId) {
        headerScopes.delete(connectorId);
        reportedScopes.delete(connectorId);
      } else {
        headerScopes.clear();
        reportedScopes.clear();
      }
    },

    async revokeAll(): Promise<RevokeResult[]> {
      const out: RevokeResult[] = [];
      for (const id of tokens.cachedIds()) {
        let conn: ResolvedConnector | undefined;
        try {
          conn = await opts.getConnector(id);
        } catch {
          conn = undefined;
        }
        if (!conn) {
          tokens.invalidate(id);
          out.push({ connectorId: id, revoked: false, detail: "config unavailable; token dropped from memory" });
          continue;
        }
        const c = conn;
        try {
          const r = await tokens.revoke(c, opts.secrets, async (url, h, b) => {
            checkPolicy(c, "POST", url.href, "revoke");
            const res = (await send(c, "POST", url, h, b)).res;
            await opts.audit?.({ connectorId: c.metadata.id, action: "revoke", method: "POST", host: url.host, path: url.pathname, status: res.status, decision: res.status < 300 ? "allow" : `error: HTTP ${res.status}` });
            return res;
          }, clock.now());
          out.push({ connectorId: id, ...r });
        } catch (e) {
          out.push({ connectorId: id, revoked: false, detail: `revocation failed: ${(e as Error).message}` });
        }
      }
      tokens.invalidate();
      return out;
    },
  };
}

function checkPolicy(conn: ResolvedConnector, method: string, rawUrl: string, target: Target): URL {
  // Disabled connectors make no calls, except revoking their own token during panic.
  if (target !== "revoke" && (conn as { status?: string }).status === "disabled")
    throw new BrokerError("policy_denied", "policy denied: connector is disabled");
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new BrokerError("policy_denied", "invalid URL");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw deny(conn, method, url, `scheme ${url.protocol} not allowed`);
  if (url.username || url.password) throw deny(conn, method, url, "credentials in URL");
  if (!hostAllowed(url.hostname, conn.policy.allowed_hosts)) throw deny(conn, method, url, `host ${url.hostname} not in allowed_hosts`);
  const rt = conn.runtime;
  if (target === "token") {
    if (method !== "POST" || url.pathname !== rt.tokenPath) throw deny(conn, method, url, "not the configured token endpoint");
  } else if (target === "revoke") {
    if (method !== "POST" || url.href !== rt.revocationUrl) throw deny(conn, method, url, "not the configured revocation endpoint");
  } else if (method === "POST") {
    if (!pathAllowed(url.pathname, rt.readOnlyPost)) throw deny(conn, method, url, `POST to ${url.pathname} not in read_only_post`);
  } else {
    if (!methodAllowed(method, rt.methods)) throw deny(conn, method, url, `method ${method} not allowed`);
    if (!pathAllowed(url.pathname, rt.allowedPaths) || url.pathname === rt.tokenPath)
      throw deny(conn, method, url, `path ${url.pathname} not in allowed_paths`);
  }
  return url;
}

function deny(conn: ResolvedConnector, method: string, url: URL | undefined, reason: string): BrokerError {
  log.warn({ connector: conn.metadata.id, method, host: url?.host, path: url?.pathname, decision: "deny", reason }, "policy denied");
  return new BrokerError("policy_denied", `policy denied: ${reason}`);
}

function scrubText(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    if (s.length < 6) continue;
    for (const form of [s, encodeURIComponent(s)]) if (out.includes(form)) out = out.split(form).join("[REDACTED:secret]");
  }
  return out;
}
function scrubValues(h: Record<string, string>, secrets: string[]): Record<string, string> {
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k, scrubText(v, secrets)]));
}
