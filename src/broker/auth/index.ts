// Auth strategies. Each mutates the outgoing headers/URL and returns the secret values it used
// (so the broker can scrub them from responses and logs).
import type { ConnectorConfig } from "../../config/schema.ts";
import { BrokerError, type SecretSource } from "../types.ts";

export type AuthTarget = { url: URL; headers: Record<string, string> };
type Auth = ConnectorConfig["connection"]["auth"];

async function need(secrets: SecretSource, tenant: string, ref: string): Promise<string> {
  const v = await secrets.get(tenant, ref);
  if (!v) throw new BrokerError("secret_missing", `secret "${ref}" is not set (ix secret set ${ref})`);
  return v;
}

export async function applyAuth(auth: Auth, tenant: string, target: AuthTarget, secrets: SecretSource): Promise<string[]> {
  switch (auth.type) {
    case "none":
      return [];
    case "api_key": {
      const v = await need(secrets, tenant, auth.secret_ref);
      const value = `${auth.prefix ?? ""}${v}`;
      if (auth.in === "header") target.headers[auth.name.toLowerCase()] = value;
      else target.url.searchParams.set(auth.name, value);
      return [v];
    }
    case "bearer": {
      const v = await need(secrets, tenant, auth.secret_ref);
      target.headers.authorization = `Bearer ${v}`;
      return [v];
    }
    case "basic": {
      const u = await need(secrets, tenant, auth.username_ref);
      const p = await need(secrets, tenant, auth.password_ref);
      const b64 = Buffer.from(`${u}:${p}`).toString("base64");
      target.headers.authorization = `Basic ${b64}`;
      return [p, b64];
    }
    case "oauth2_client_credentials":
      throw new BrokerError("secret_missing", "oauth2_client_credentials is not implemented yet (Phase 4)");
  }
}