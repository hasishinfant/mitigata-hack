// Two env files, so secrets can't leak into processes that shouldn't have them:
//   .env         app settings for api / scheduler / worker / CLI (no broker credentials)
//   .env.broker  IX_MASTER_KEY, DATABASE_URL_BROKER, DATABASE_URL_ADMIN: loaded by the broker and migrate only
// Values already in the environment win (process.loadEnvFile does not override).

export const BROKER_ONLY_VARS = ["IX_MASTER_KEY", "DATABASE_URL_BROKER", "DATABASE_URL_ADMIN"] as const;

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

export function loadBrokerEnv(): void {
  load(".env");
  load(".env.broker");
}

/** Names (never values) of broker-only secrets present in an environment. */
export function brokerSecretsIn(env: Record<string, string | undefined>): string[] {
  return Object.keys(env).filter((k) => env[k] && ((BROKER_ONLY_VARS as readonly string[]).includes(k) || k.startsWith("IX_SECRET_")));
}

/** Workers, API and scheduler refuse to start with broker secrets in their environment (fail closed). */
export function assertNoBrokerSecrets(processName: string, env: Record<string, string | undefined> = process.env): void {
  const found = brokerSecretsIn(env);
  if (found.length)
    throw new Error(`${processName} refuses to start: broker-only secrets in its environment (${found.join(", ")}). Keep them in .env.broker.`);
}

/** Copy of an environment with broker-only secrets removed (for spawning non-broker processes). */
export function withoutBrokerSecrets(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out = { ...env };
  for (const k of brokerSecretsIn(env)) delete out[k];
  return out;
}
