// OAuth2 client-credentials grant. Tokens live only in broker memory, are refreshed 60 s before
// expiry, and are dropped on demand (401, disable, panic). Supports client_secret_basic,
// client_secret_post and private_key_jwt (RFC 7523 client assertion).
import { createPrivateKey, randomUUID, type KeyObject } from "node:crypto";
import { SignJWT } from "jose";
import type { ResolvedConnector } from "../../config/load.ts";
import type { HttpResult } from "../http.ts";
import { BrokerError, type SecretSource } from "../types.ts";

type OAuthCfg = Extract<ResolvedConnector["connection"]["auth"], { type: "oauth2_client_credentials" }>;
export type TokenSender = (url: URL, headers: Record<string, string>, body: string) => Promise<HttpResult>;
export type CachedToken = { token: string; expiresAt: number; scopes?: string[] };

const REFRESH_EARLY_MS = 60_000;
const DEFAULT_TTL_MS = 3_600_000;
const ASSERTION_TTL_S = 300;

async function need(secrets: SecretSource, tenant: string, ref: string | undefined, what: string): Promise<string> {
  if (!ref) throw new BrokerError("secret_missing", `${what} ref is not configured`);
  const v = await secrets.get(tenant, ref);
  if (!v) throw new BrokerError("secret_missing", `secret "${ref}" is not set (ix secret set ${ref})`);
  return v;
}

export function loadSigningKey(material: string): { key: KeyObject; alg: string } {
  const text = material.trim();
  let key: KeyObject;
  try {
    key = text.startsWith("{") ? createPrivateKey({ key: JSON.parse(text), format: "jwk" }) : createPrivateKey(text);
  } catch {
    throw new BrokerError("secret_missing", "private key is not a valid PEM or JWK private key");
  }
  const type = key.asymmetricKeyType;
  if (type === "rsa") return { key, alg: "RS256" };
  if (type === "ec") {
    const curve = key.asymmetricKeyDetails?.namedCurve;
    return { key, alg: curve === "secp384r1" ? "ES384" : curve === "secp521r1" ? "ES512" : "ES256" };
  }
  throw new BrokerError("secret_missing", `unsupported private key type ${type}`);
}

/** Build the RFC 7523 client assertion: iss = sub = client_id, aud = token endpoint. */
export async function clientAssertion(clientId: string, audience: string, keyMaterial: string, keyId: string | undefined, nowMs: number) {
  const { key, alg } = loadSigningKey(keyMaterial);
  const iat = Math.floor(nowMs / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg, typ: "JWT", ...(keyId ? { kid: keyId } : {}) })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audience)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ASSERTION_TTL_S)
    .setJti(randomUUID())
    .sign(key);
}

export class OAuthTokenManager {
  private cache = new Map<string, CachedToken>();

  peek(connectorId: string): CachedToken | undefined {
    return this.cache.get(connectorId);
  }
  invalidate(connectorId?: string): void {
    if (connectorId) this.cache.delete(connectorId);
    else this.cache.clear();
  }

  /** Returns a valid access token plus the secret values involved (for scrubbing). */
  async get(conn: ResolvedConnector, secrets: SecretSource, send: TokenSender, now: number): Promise<{ token: string; used: string[] }> {
    const hit = this.cache.get(conn.metadata.id);
    if (hit && hit.expiresAt - REFRESH_EARLY_MS > now) return { token: hit.token, used: [hit.token] };

    const auth = conn.connection.auth as OAuthCfg;
    const tenant = conn.metadata.tenant;
    const tokenUrl = new URL(auth.token_url, conn.connection.base_url);
    const clientId = await need(secrets, tenant, auth.client_id_ref, "client_id");
    const form = new URLSearchParams({ grant_type: "client_credentials" });
    if (auth.scopes?.length) form.set("scope", auth.scopes.join(" "));
    const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
    const used: string[] = [];

    if (auth.client_auth === "private_key_jwt") {
      const pem = await need(secrets, tenant, auth.private_key_ref, "private_key");
      const assertion = await clientAssertion(clientId, auth.audience ?? tokenUrl.href, pem, auth.key_id, now);
      form.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      form.set("client_assertion", assertion);
      used.push(pem, assertion);
    } else {
      const secret = await need(secrets, tenant, auth.client_secret_ref, "client_secret");
      used.push(secret);
      if (auth.client_auth === "client_secret_basic") {
        const b64 = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`).toString("base64");
        headers.authorization = `Basic ${b64}`;
        used.push(b64);
      } else {
        form.set("client_id", clientId);
        form.set("client_secret", secret);
      }
    }
    if (auth.audience && auth.client_auth !== "private_key_jwt") form.set("audience", auth.audience);

    const res = await send(tokenUrl, headers, form.toString());
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(res.body) as Record<string, unknown>;
    } catch {
      /* handled below */
    }
    if (res.status < 200 || res.status >= 300 || typeof json.access_token !== "string") {
      const code = typeof json.error === "string" ? json.error : `HTTP ${res.status}`;
      const desc = typeof json.error_description === "string" ? `: ${json.error_description.slice(0, 200)}` : "";
      const kind = res.status >= 500 ? "network" : "auth_failed";
      throw new BrokerError(kind, `token request failed (${code}${desc})`);
    }
    const ttl = typeof json.expires_in === "number" ? json.expires_in * 1000 : Number(json.expires_in) * 1000 || DEFAULT_TTL_MS;
    const scopes = typeof json.scope === "string" && json.scope.trim() ? json.scope.trim().split(/\s+/) : undefined;
    const cached: CachedToken = { token: json.access_token, expiresAt: now + ttl, ...(scopes ? { scopes } : {}) };
    this.cache.set(conn.metadata.id, cached);
    return { token: cached.token, used: [...used, cached.token] };
  }
}
