// Two env files, so secrets can't leak into processes that shouldn't have them:
//   .env         app settings for api / scheduler / worker / CLI (no broker credentials)
//   .env.broker  IX_MASTER_KEY, DATABASE_URL_BROKER, DATABASE_URL_ADMIN: loaded by the broker and migrate only
//   .env.admin   IX_BROKER_ADMIN_TOKEN: unlocks the broker's admin socket; loaded by the broker, API and CLI only
// Values already in the environment win (process.loadEnvFile does not override).

export const BROKER_ONLY_VARS = ["IX_MASTER_KEY", "DATABASE_URL_BROKER", "DATABASE_URL_ADMIN"] as const;
/** Held by the broker, API and CLI. Workers and the scheduler must never have it. */
export const ADMIN_TOKEN_VAR = "IX_BROKER_ADMIN_TOKEN";

function load(file: string): void {
  try {
    process.loadEnvFile(file);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
}

export function loadAppEnv(): void {
  load(".env");
}

/** API and CLI: app settings plus the broker admin token. */
export function loadAdminEnv(): void {
  load(".env");
  load(".env.admin");
}

export function loadBrokerEnv(): void {
  load(".env");
  load(".env.broker");
  load(".env.admin");
}

/** Names (never values) of broker-only secrets present in an environment. */
export function brokerSecretsIn(env: Record<string, string | undefined>): string[] {
  return Object.keys(env).filter((k) => env[k] && ((BROKER_ONLY_VARS as readonly string[]).includes(k) || k.startsWith("IX_SECRET_")));
}

/**
 * Workers, API and scheduler refuse to start with broker secrets in their environment (fail closed).
 * Workers and the scheduler also refuse the broker admin token (adminTokenAllowed: false).
 */
export function assertNoBrokerSecrets(
  processName: string,
  env: Record<string, string | undefined> = process.env,
  opts: { adminTokenAllowed?: boolean } = {},
): void {
  const found = brokerSecretsIn(env);
  if (!opts.adminTokenAllowed && env[ADMIN_TOKEN_VAR]) found.push(ADMIN_TOKEN_VAR);
  if (found.length)
    throw new Error(`${processName} refuses to start: broker-only secrets in its environment (${found.join(", ")}). Keep them in .env.broker / .env.admin.`);
}

/** Copy of an environment with broker-only secrets (and, by default, the admin token) removed, for spawning non-broker processes. */
export function withoutBrokerSecrets(env: NodeJS.ProcessEnv, opts: { keepAdminToken?: boolean } = {}): NodeJS.ProcessEnv {
  const out = { ...env };
  for (const k of brokerSecretsIn(env)) delete out[k];
  if (!opts.keepAdminToken) delete out[ADMIN_TOKEN_VAR];
  return out;
}
