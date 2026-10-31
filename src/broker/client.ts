// In-process broker. Phase 6 moves this behind a socket in its own process;
// the Broker interface stays the same so workers don't change.
// Every outbound call gets: policy check, auth, token-bucket throttle, retry with backoff,
// 429 / Retry-After handling, and response scrubbing.
import type { ResolvedConnector } from "../config/load.ts";
import { log, registerSecretForScrub } from "../log.ts";
import { applyAuth } from "./auth/index.ts";
import { httpCall, type HttpResult } from "./http.ts";
import { hostAllowed, methodAllowed, pathAllowed } from "./policy.ts";
import { backoffMs, classifyResponse, providerWaitMs, realClock, TokenBucket, type Clock } from "./retry.ts";
import { BrokerError, type Broker, type BrokerRequest, type BrokerResponse, type SecretSource } from "./types.ts";

const MAX_BYTES = 64 * 1024 * 1024;
const MAX_RATE_LIMIT_WAITS = 5;
const FORBIDDEN_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "host", "x-api-key"]);

export type LocalBrokerOptions = {
  getConnector: (id: string) => ResolvedConnector | undefined;
  secrets: SecretSource;
  clock?: Clock;
  random?: () => number;
};

export function createLocalBroker(opts: LocalBrokerOptions): Broker {
  const clock = opts.clock ?? realClock;
  const buckets = new Map<string, TokenBucket>();
  const bucketFor = (conn: ResolvedConnector): TokenBucket => {
    const rpm = conn.runtime.rateLimit.requestsPerMinute;
    let b = buckets.get(conn.metadata.id);
    if (!b || b.rpm !== rpm) buckets.set(conn.metadata.id, (b = new TokenBucket(rpm, clock.now())));
    return b;
  };

  return {
    async request(req: BrokerRequest): Promise<BrokerResponse> {
      const conn = opts.getConnector(req.connectorId);
      if (!conn) throw new BrokerError("unknown_connector", `connector ${req.connectorId} is not registered with the broker`);
      const url = checkPolicy(conn, req);

      const headers: Record<string, string> = { "user-agent": "IntegrateX/0.1", accept: "application/json" };
      for (const [k, v] of Object.entries(req.headers ?? {})) {
        const name = k.toLowerCase();
        if (FORBIDDEN_HEADERS.has(name)) throw deny(conn, req, url, `header ${name} may not be set by workers`);
        headers[name] = v;
      }
      const used = await applyAuth(conn.connection.auth, conn.metadata.tenant, { url, headers }, opts.secrets);
      used.forEach(registerSecretForScrub);

      const { retries: retryCfg, rateLimit, timeoutMs } = conn.runtime;
      const where = { connector: conn.metadata.id, host: url.host, path: url.pathname };
      let errorAttempts = 0; // consumed by timeouts / network errors / 5xx
      let rateWaits = 0; // consumed by 429 / rate-limit 403
      let rateLimitedMs = 0;
      const retries = () => errorAttempts + rateWaits;
      const started = clock.now();

      for (;;) {
        await bucketFor(conn).take(clock);
        let res: HttpResult;
        try {
          res = await httpCall("GET", url, headers, { timeoutMs, maxBytes: MAX_BYTES });
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
        log.info({ ...where, method: "GET", status: res.status, attempt: retries() + 1 }, "outbound");

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

        // A provider may echo a credential back (e.g. a query-string key inside a Link header). Strip it.
        return {
          status: res.status,
          headers: scrubValues(res.headers, used),
          body: scrubText(res.body, used),
          durationMs: clock.now() - started,
          retries: retries(),
          rateLimitedMs,
        };
      }
    },
  };
}

function checkPolicy(conn: ResolvedConnector, req: BrokerRequest): URL {
  let url: URL;
  try {
    url = new URL(req.url);
  } catch {
    throw new BrokerError("policy_denied", "invalid URL");
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw deny(conn, req, url, `scheme ${url.protocol} not allowed`);
  if (url.username || url.password) throw deny(conn, req, url, "credentials in URL");
  if (!methodAllowed(req.method, conn.runtime.methods)) throw deny(conn, req, url, `method ${req.method} not allowed`);
  if (!hostAllowed(url.hostname, conn.policy.allowed_hosts)) throw deny(conn, req, url, `host ${url.hostname} not in allowed_hosts`);
  if (!pathAllowed(url.pathname, conn.runtime.allowedPaths)) throw deny(conn, req, url, `path ${url.pathname} not in allowed_paths`);
  return url;
}

function deny(conn: ResolvedConnector, req: BrokerRequest, url: URL | undefined, reason: string): BrokerError {
  log.warn({ connector: conn.metadata.id, method: req.method, host: url?.host, path: url?.pathname, decision: "deny", reason }, "policy denied");
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
