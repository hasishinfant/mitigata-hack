// Client for the broker process. Used by workers, the API and the CLI. Holds no provider secrets:
// it sends "fetch this URL for connector X" and gets back status, headers and body.
// Admin operations go to the separate admin socket and need IX_BROKER_ADMIN_TOKEN, which only the
// API and CLI load (.env.admin). Workers and the scheduler never have it.
import { request as httpRequest, Agent } from "node:http";
import type { ConnectionTest } from "../engine/testConnection.ts";
import type { RegisterResult } from "../store/connectors.ts";
import type { LedgerCheck } from "./ledger.ts";
import { BrokerError, type Broker, type BrokerErrorKind, type BrokerRequest, type BrokerResponse, type CredentialInfo } from "./types.ts";

export type SecretMeta = { tenant_id: string; ref: string; created_at: string; last_used_at: string | null; granted_scopes: string[] | null; age_days: number };

/** Admin operations the API and CLI need. All values flow one way: into the broker. */
export interface BrokerAdmin {
  register(yaml: string, mode: "add" | "update", createdBy?: string, opts?: { confirmHosts?: boolean }): Promise<RegisterResult>;
  putSecret(tenant: string, ref: string, value: string): Promise<{ ok: true; chars: number }>;
  listSecrets(tenant?: string): Promise<SecretMeta[]>;
  deleteSecret(tenant: string, ref: string): Promise<boolean>;
  testInline(yaml: string): Promise<ConnectionTest>;
  verifyLedger(): Promise<LedgerCheck>;
  forget(connectorId?: string): Promise<void>;
  ping(): Promise<boolean>;
  panic(opts: { purgeSecrets?: boolean; actor?: string }): Promise<{ revocations: { connectorId: string; revoked: boolean; detail: string }[]; purged: number }>;
  notify(connectorId: string, text: string): Promise<{ delivered: boolean; channel: string; detail: string }>;
  /** Re-enable a disabled connector (broker-only: the app DB role can disable but not re-enable). */
  enableConnector(id: string): Promise<{ id: string; status: string }>;
  removeConnector(id: string, opts?: { purgeSecrets?: boolean }): Promise<{ removed: boolean; records: number; secrets?: { deleted: string[]; kept_shared: string[] } }>;
}
export type RemoteBroker = Broker & BrokerAdmin;

export class BrokerUnavailable extends Error {}

export function defaultSocketPath(env = process.env): string {
  return env.IX_BROKER_SOCKET || "/tmp/ix-broker.sock";
}
export function defaultAdminSocketPath(env = process.env): string {
  return env.IX_BROKER_ADMIN_SOCKET || "/tmp/ix-broker-admin.sock";
}

export const ADMIN_HEADER = "x-ix-broker-admin";

export function createRemoteBroker(
  socketPath = defaultSocketPath(),
  opts: { adminSocketPath?: string; adminToken?: string } = {},
): RemoteBroker {
  const agent = new Agent({ keepAlive: true, maxSockets: 16 });
  const adminSocket = opts.adminSocketPath ?? defaultAdminSocketPath();
  const adminToken = opts.adminToken ?? process.env.IX_BROKER_ADMIN_TOKEN;

  const call = <T>(method: string, path: string, body?: unknown) => send<T>(socketPath, {}, method, path, body);
  const admin = <T>(method: string, path: string, body?: unknown): Promise<T> => {
    if (!adminToken) return Promise.reject(new Error("IX_BROKER_ADMIN_TOKEN is not set (it lives in .env.admin; only the API and CLI load it)"));
    return send<T>(adminSocket, { [ADMIN_HEADER]: adminToken }, method, path, body);
  };

  function send<T>(sock: string, extra: Record<string, string>, method: string, path: string, body?: unknown): Promise<T> {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        {
          socketPath: sock, path, method, agent,
          headers: { ...extra, ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}) },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            let json: { error?: { kind?: string; message?: string; retries?: number; rateLimitedMs?: number; issues?: unknown } } & Record<string, unknown>;
            try {
              json = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
            } catch {
              return reject(new Error(`broker returned invalid JSON (HTTP ${res.statusCode})`));
            }
            if ((res.statusCode ?? 500) >= 400) {
              const e = json.error ?? {};
              const known: BrokerErrorKind[] = ["policy_denied", "secret_missing", "auth_failed", "tls", "timeout", "network", "too_large", "unknown_connector", "rate_limited"];
              if (e.kind && known.includes(e.kind as BrokerErrorKind)) {
                const err = new BrokerError(e.kind as BrokerErrorKind, e.message ?? "broker error");
                err.retries = e.retries ?? 0;
                err.rateLimitedMs = e.rateLimitedMs ?? 0;
                return reject(err);
              }
              return reject(Object.assign(new Error(e.message ?? `broker HTTP ${res.statusCode}`), { statusCode: res.statusCode, issues: e.issues }));
            }
            resolve(json as T);
          });
          res.on("error", reject);
        },
      );
      req.on("error", (e: NodeJS.ErrnoException) => {
        if (e.code === "ENOENT" || e.code === "ECONNREFUSED")
          reject(new BrokerUnavailable(`broker is not running on ${sock} (start it with: npx pnpm@10.28.0 broker)`));
        else reject(e);
      });
      if (payload) req.write(payload);
      req.end();
    });
  }

  return {
    request: (r: BrokerRequest) => call<BrokerResponse>("POST", "/v1/request", r),
    credentialInfo: (id) => call<CredentialInfo>("GET", `/v1/credential-info/${encodeURIComponent(id)}`),
    register: (yaml, mode, createdBy, o) => admin<RegisterResult>("POST", "/v1/connectors", { yaml, mode, createdBy, confirmHosts: o?.confirmHosts === true }),
    putSecret: (tenant, ref, value) => admin("PUT", `/v1/secrets/${encodeURIComponent(tenant)}/${encodeURIComponent(ref)}`, { value }),
    listSecrets: async (tenant) => (await admin<{ secrets: SecretMeta[] }>("GET", `/v1/secrets${tenant ? `?tenant=${encodeURIComponent(tenant)}` : ""}`)).secrets,
    deleteSecret: async (tenant, ref) => (await admin<{ deleted: boolean }>("DELETE", `/v1/secrets/${encodeURIComponent(tenant)}/${encodeURIComponent(ref)}`)).deleted,
    testInline: (yaml) => admin<ConnectionTest>("POST", "/v1/test-inline", { yaml }),
    verifyLedger: () => admin<LedgerCheck>("GET", "/v1/ledger/verify"),
    panic: (o) => admin("POST", "/v1/panic", o),
    notify: (connectorId, text) => call("POST", "/v1/notify", { connectorId, text }),
    enableConnector: (id) => admin("POST", `/v1/connectors/${encodeURIComponent(id)}/enable`, {}),
    removeConnector: (id, o) => admin("DELETE", `/v1/connectors/${encodeURIComponent(id)}${o?.purgeSecrets ? "?purge_secrets=1" : ""}`),
    forget: async (connectorId) => {
      await call("POST", "/v1/forget", { connectorId });
    },
    ping: async () => {
      try {
        await call("GET", "/v1/ping");
        return true;
      } catch {
        return false;
      }
    },
  };
}
