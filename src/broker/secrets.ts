// Secret sources for the broker.
// DB store: envelope encryption. Each secret gets its own random 256-bit data key (DEK); the value is
// encrypted with AES-256-GCM under the DEK, and the DEK is wrapped with AES-256-GCM under the master key
// (IX_MASTER_KEY). Both use AAD = "tenant/ref", so a ciphertext row moved to another ref fails to decrypt.
// Only the ix_broker DB role can read the credentials table.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type pg from "pg";
import type { SecretSource } from "./types.ts";

export type Sealed = { ciphertext: Buffer; wrappedDek: Buffer; nonce: Buffer };

export function parseMasterKey(b64: string | undefined): Buffer {
  if (!b64) throw new Error("IX_MASTER_KEY is not set (generate with: openssl rand -base64 32)");
  const key = Buffer.from(b64, "base64");
  if (key.length !== 32) throw new Error("IX_MASTER_KEY must be 32 bytes, base64-encoded");
  return key;
}

function gcmEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(aad);
  return Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
}
function gcmDecrypt(key: Buffer, nonce: Buffer, data: Buffer, aad: Buffer): Buffer {
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(aad);
  d.setAuthTag(data.subarray(data.length - 16));
  return Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]);
}

export function seal(masterKey: Buffer, tenant: string, ref: string, value: string): Sealed {
  const aad = Buffer.from(`${tenant}/${ref}`);
  const dek = randomBytes(32);
  const nonce = randomBytes(12);
  const ciphertext = gcmEncrypt(dek, nonce, Buffer.from(value, "utf8"), aad);
  const wrapNonce = randomBytes(12);
  const wrappedDek = Buffer.concat([wrapNonce, gcmEncrypt(masterKey, wrapNonce, dek, aad)]);
  dek.fill(0);
  return { ciphertext, wrappedDek, nonce };
}

export function unseal(masterKey: Buffer, tenant: string, ref: string, s: Sealed): string {
  const aad = Buffer.from(`${tenant}/${ref}`);
  const dek = gcmDecrypt(masterKey, s.wrappedDek.subarray(0, 12), s.wrappedDek.subarray(12), aad);
  try {
    return gcmDecrypt(dek, s.nonce, s.ciphertext, aad).toString("utf8");
  } finally {
    dek.fill(0);
  }
}

export async function putSecret(pool: pg.Pool, masterKey: Buffer, tenant: string, ref: string, value: string): Promise<void> {
  const s = seal(masterKey, tenant, ref, value);
  await pool.query("insert into tenants (id, name) values ($1, $1) on conflict do nothing", [tenant]);
  // Rotation resets created_at (credential age) and clears scope info until the next use.
  await pool.query(
    `insert into credentials (ref, tenant_id, ciphertext, wrapped_dek, nonce, created_at, last_used_at, granted_scopes)
     values ($1, $2, $3, $4, $5, now(), null, null)
     on conflict (tenant_id, ref) do update set ciphertext = excluded.ciphertext, wrapped_dek = excluded.wrapped_dek,
       nonce = excluded.nonce, created_at = now(), last_used_at = null, granted_scopes = null`,
    [ref, tenant, s.ciphertext, s.wrappedDek, s.nonce],
  );
}

export async function deleteSecret(pool: pg.Pool, tenant: string, ref: string): Promise<boolean> {
  return ((await pool.query("delete from credentials where tenant_id = $1 and ref = $2", [tenant, ref])).rowCount ?? 0) > 0;
}

/** Metadata only. Values never leave the store through this function. */
export async function listSecrets(pool: pg.Pool, tenant?: string) {
  return (
    await pool.query(
      `select tenant_id, ref, created_at, last_used_at, granted_scopes,
              floor(extract(epoch from now() - created_at) / 86400)::int as age_days
       from credentials where ($1::text is null or tenant_id = $1) order by tenant_id, ref`,
      [tenant ?? null],
    )
  ).rows;
}

export function dbSecretSource(pool: pg.Pool, masterKey: Buffer): SecretSource & { forget(): void } {
  const cache = new Map<string, { value: string; at: number }>();
  const TTL = 60_000;
  return {
    async get(tenant, ref) {
      const key = `${tenant}/${ref}`;
      const hit = cache.get(key);
      if (hit && Date.now() - hit.at < TTL) return hit.value;
      const r = await pool.query("select ciphertext, wrapped_dek, nonce from credentials where tenant_id = $1 and ref = $2", [tenant, ref]);
      if (!r.rowCount) return undefined;
      const row = r.rows[0];
      const value = unseal(masterKey, tenant, ref, { ciphertext: row.ciphertext, wrappedDek: row.wrapped_dek, nonce: row.nonce });
      await pool.query("update credentials set last_used_at = now() where tenant_id = $1 and ref = $2", [tenant, ref]);
      cache.set(key, { value, at: Date.now() });
      return value;
    },
    forget() {
      cache.clear();
    },
  };
}

/** Dev/test only: IX_SECRET_<REF> from the environment of the process running the broker. */
export function envSecretSource(env: Record<string, string | undefined> = process.env): SecretSource {
  return {
    async get(_tenant, ref) {
      return env[`IX_SECRET_${ref.toUpperCase()}`] || undefined;
    },
  };
}

/** First source that has the secret wins. */
export function chainSecretSources(...sources: SecretSource[]): SecretSource {
  return {
    async get(tenant, ref) {
      for (const s of sources) {
        const v = await s.get(tenant, ref);
        if (v) return v;
      }
      return undefined;
    },
  };
}
