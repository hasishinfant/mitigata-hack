// In-process broker (Phase 2). Phase 6 moves this behind a socket in its own process;
// the Broker interface stays the same so workers don't change.
import type { ResolvedConnector } from "../config/load.ts";
import { log, registerSecretForScrub } from "../log.ts";
import { applyAuth } from "./auth/index.ts";
import { httpCall } from "./http.ts";
import { hostAllowed, methodAllowed, pathAllowed } from "./policy.ts";
import { BrokerError, type Broker, type BrokerRequest, type BrokerResponse, type SecretSource } from "./types.ts";

const MAX_BYTES = 64 * 1024 * 1024;
const FORBIDDEN_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "host", "x-api-key"]);

export type LocalBrokerOptions = {
  getConnector: (id: string) => ResolvedConnector | undefined;
  secrets: SecretSource;
};

export function createLocalBroker(opts: LocalBrokerOptions): Broker {
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

      const started = Date.now();
      const res = await httpCall("GET", url, headers, { timeoutMs: conn.runtime.timeoutMs, maxBytes: MAX_BYTES });
      const durationMs = Date.now() - started;
      log.info({ connector: conn.metadata.id, method: "GET", host: url.host, path: url.pathname, status: res.status, ms: durationMs }, "outbound");

      // A provider may echo a credential back (e.g. a query-string key inside a Link header). Strip it.
      return { status: res.status, headers: scrubValues(res.headers, used), body: scrubText(res.body, used), durationMs };
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
