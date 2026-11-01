// OAuth2 client-credentials grant. Tokens live only in broker memory, are refreshed 60 s before
// expiry, and are dropped on demand (401, disable, panic). Supports client_secret_basic,
// client_secret_post and private_key_jwt (RFC 7523 client assertion).
import { createHash, createPrivateKey, randomUUID, type KeyObject } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import type { ResolvedConnector } from "../../config/load.ts";
import type { HttpResult } from "../http.ts";
import { BrokerError, type SecretSource } from "../types.ts";

type OAuthCfg = Extract<ResolvedConnector["connection"]["auth"], { type: "oauth2_client_credentials" }>;
/** headers() is called for every attempt (including retries), so each attempt gets a fresh DPoP proof. */
export type TokenSender = (url: URL, headers: () => Promise<Record<string, string>>, body: string) => Promise<HttpResult>;
export type CachedToken = { token: string; expiresAt: number; scopes?: string[]; dpop?: boolean };
type DpopKey = { privateKey: CryptoKey | KeyObject; jwk: JWK };

const b64u = (b: Buffer) => b.toString("base64url");
/** ath claim: base64url(sha256(access token)). */
export const accessTokenHash = (token: string) => b64u(createHash("sha256").update(token).digest());

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
  // DPoP: one key per connector token, generated in memory, never stored or exported; dropped with the token.
  private dpopKeys = new Map<string, DpopKey>();
  private nonces = new Map<string, string>(); // server origin -> last DPoP-Nonce it asked for

  /** A DPoP proof JWT (RFC 9449 §4) for one request. htu = URL without query and fragment. */
  async dpopProof(connectorId: string, method: string, url: URL, now: number, accessToken?: string): Promise<string> {
    let key = this.dpopKeys.get(connectorId);
    if (!key) {
      const { privateKey, publicKey } = await generateKeyPair("ES256");
      const jwk = await exportJWK(publicKey);
      key = { privateKey, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
      this.dpopKeys.set(connectorId, key);
    }
    const nonce = this.nonces.get(url.origin);
    return new SignJWT({
      htm: method.toUpperCase(), htu: `${url.origin}${url.pathname}`, jti: randomUUID(),
      ...(accessToken ? { ath: accessTokenHash(accessToken) } : {}), ...(nonce ? { nonce } : {}),
    })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: key.jwk })
      .setIssuedAt(Math.floor(now / 1000))
      .sign(key.privateKey);
  }

  /** Remember a server-supplied nonce (DPoP-Nonce header). Returns true if it changed (worth one retry). */
  learnNonce(url: URL, headers: Record<string, string>): boolean {
    const n = headers["dpop-nonce"];
    if (!n || this.nonces.get(url.origin) === n) return false;
    this.nonces.set(url.origin, n);
    return true;
  }

  peek(connectorId: string): CachedToken | undefined {
    return this.cache.get(connectorId);
  }
  invalidate(connectorId?: string): void {
    // The DPoP key goes with the token: the next token is bound to a brand-new key.
    if (connectorId) {
      this.cache.delete(connectorId);
      this.dpopKeys.delete(connectorId);
    } else {
      this.cache.clear();
      this.dpopKeys.clear();
    }
  }

  /** Client authentication for the token or revocation endpoint (RFC 6749 §2.3 / RFC 7523). */
  private async clientAuth(conn: ResolvedConnector, secrets: SecretSource, audience: string, now: number) {
    const auth = conn.connection.auth as OAuthCfg;
    const tenant = conn.metadata.tenant;
    const clientId = await need(secrets, tenant, auth.client_id_ref, "client_id");
    const form = new URLSearchParams();
    const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
    const used: string[] = [];
    if (auth.client_auth === "private_key_jwt") {
      const pem = await need(secrets, tenant, auth.private_key_ref, "private_key");
      const assertion = await clientAssertion(clientId, audience, pem, auth.key_id, now);
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
    return { headers, form, used };
  }

  /** Returns a valid access token plus the secret values involved (for scrubbing). */
  async get(conn: ResolvedConnector, secrets: SecretSource, send: TokenSender, now: number): Promise<{ token: string; used: string[]; dpop?: boolean }> {
    const hit = this.cache.get(conn.metadata.id);
    if (hit && hit.expiresAt - REFRESH_EARLY_MS > now) return { token: hit.token, used: [hit.token], ...(hit.dpop ? { dpop: true } : {}) };

    const auth = conn.connection.auth as OAuthCfg;
    const tokenUrl = new URL(auth.token_url, conn.connection.base_url);
    const { headers, form, used } = await this.clientAuth(conn, secrets, auth.audience ?? tokenUrl.href, now);
    form.set("grant_type", "client_credentials");
    if (auth.scopes?.length) form.set("scope", auth.scopes.join(" "));
    if (auth.audience && auth.client_auth !== "private_key_jwt") form.set("audience", auth.audience);

    const useDpop = auth.dpop === true;
    const attempt = () => send(tokenUrl, async () => (useDpop ? { ...headers, dpop: await this.dpopProof(conn.metadata.id, "POST", tokenUrl, Date.now()) } : headers), form.toString());
    const parse = (r: HttpResult): Record<string, unknown> => {
      try {
        return JSON.parse(r.body) as Record<string, unknown>;
      } catch {
        return {};
      }
    };
    let res = await attempt();
    let json = parse(res);
    // RFC 9449 §8: the server may demand a nonce; retry once with it.
    if (useDpop && res.status === 400 && json.error === "use_dpop_nonce" && this.learnNonce(tokenUrl, res.headers)) {
      res = await attempt();
      json = parse(res);
    }
    if (res.status < 200 || res.status >= 300 || typeof json.access_token !== "string") {
      const code = typeof json.error === "string" ? json.error : `HTTP ${res.status}`;
      const desc = typeof json.error_description === "string" ? `: ${json.error_description.slice(0, 200)}` : "";
      const kind = res.status >= 500 ? "network" : "auth_failed";
      throw new BrokerError(kind, `token request failed (${code}${desc})`);
    }
    // Fail closed: a connector that requires DPoP never uses an unbound token, even if the provider issues one.
    if (useDpop && String(json.token_type ?? "").toLowerCase() !== "dpop")
      throw new BrokerError("auth_failed", `provider returned a ${String(json.token_type ?? "untyped")} token, not a DPoP-bound one; refusing it (connection.auth.dpop is set)`);
    const ttl = typeof json.expires_in === "number" ? json.expires_in * 1000 : Number(json.expires_in) * 1000 || DEFAULT_TTL_MS;
    const scopes = typeof json.scope === "string" && json.scope.trim() ? json.scope.trim().split(/\s+/) : undefined;
    const cached: CachedToken = { token: json.access_token, expiresAt: now + ttl, ...(scopes ? { scopes } : {}), ...(useDpop ? { dpop: true } : {}) };
    this.cache.set(conn.metadata.id, cached);
    return { token: cached.token, used: [...used, cached.token], ...(useDpop ? { dpop: true } : {}) };
  }

  /** Connector ids that currently hold a cached token. */
  cachedIds(): string[] {
    return [...this.cache.keys()];
  }

  /**
   * Revoke the cached access token at the connector's revocation endpoint (RFC 7009), then drop it.
   * Returns false when there's nothing to revoke or no endpoint is configured.
   */
  async revoke(conn: ResolvedConnector, secrets: SecretSource, send: TokenSender, now: number): Promise<{ revoked: boolean; detail: string }> {
    const t = this.cache.get(conn.metadata.id);
    this.cache.delete(conn.metadata.id);
    if (!t) return { revoked: false, detail: "no cached token" };
    const url = conn.runtime.revocationUrl;
    if (!url) return { revoked: false, detail: "no revocation_url configured; token dropped from memory only" };
    const { headers, form } = await this.clientAuth(conn, secrets, url, now);
    form.set("token", t.token);
    form.set("token_type_hint", "access_token");
    const res = await send(new URL(url), async () => headers, form.toString());
    return res.status >= 200 && res.status < 300
      ? { revoked: true, detail: `revoked at ${new URL(url).host}` }
      : { revoked: false, detail: `revocation endpoint answered HTTP ${res.status}` };
  }
}
