// Load a connector file, validate it, and resolve defaults into a runtime-ready shape (durations in ms).
import { readFile } from "node:fs/promises";
import type { ConnectorConfig } from "./schema.ts";
import { durationMs, validateConfigText, type Issue } from "./validate.ts";

export class ConfigError extends Error {
  file: string;
  issues: Issue[];
  constructor(file: string, issues: Issue[]) {
    super(`${file}: ${issues.length} config error(s); first: ${issues[0]?.line}:${issues[0]?.col} ${issues[0]?.message}`);
    this.file = file;
    this.issues = issues;
  }
}

export type ResolvedConnector = ConnectorConfig & {
  configHash: string;
  runtime: {
    timeoutMs: number;
    retries: { max: number; baseMs: number; jitter: boolean };
    rateLimit: { requestsPerMinute: number; respectRetryAfter: boolean; maxWaitMs: number };
    breaker: { failuresToOpen: number; coolDownMs: number };
    schedule?: { everyMs: number; jitterMs: number };
    allowedPaths: string[];
    methods: string[];
    maxRequestsPerRun: number;
    maxRecordsPerRun: number;
    anomalyMultiplier: number;
  };
};

export function resolveConnector(cfg: ConnectorConfig, configHash: string): ResolvedConnector {
  const r = cfg.reliability ?? {};
  const basePrefix = new URL(cfg.connection.base_url).pathname.replace(/\/$/, "");
  const implicitPaths = cfg.streams.map((s) => basePrefix + s.request.path);
  if (cfg.connection.auth.type === "oauth2_client_credentials")
    implicitPaths.push(new URL(cfg.connection.auth.token_url, cfg.connection.base_url).pathname);
  return {
    ...cfg,
    configHash,
    runtime: {
      timeoutMs: durationMs(r.timeout ?? "20s"),
      retries: { max: r.retries?.max ?? 3, baseMs: durationMs(r.retries?.base ?? "1s"), jitter: r.retries?.jitter ?? true },
      rateLimit: {
        requestsPerMinute: r.rate_limit?.requests_per_minute ?? 60,
        respectRetryAfter: r.rate_limit?.respect_retry_after ?? true,
        maxWaitMs: durationMs(r.rate_limit?.max_wait ?? "120s"),
      },
      breaker: {
        failuresToOpen: r.circuit_breaker?.failures_to_open ?? 5,
        coolDownMs: durationMs(r.circuit_breaker?.cool_down ?? "10m"),
      },
      ...(cfg.schedule
        ? { schedule: { everyMs: durationMs(cfg.schedule.every), jitterMs: cfg.schedule.jitter ? durationMs(cfg.schedule.jitter) : 0 } }
        : {}),
      allowedPaths: cfg.policy.allowed_paths ?? implicitPaths,
      methods: cfg.policy.methods ?? ["GET"],
      maxRequestsPerRun: cfg.policy.max_requests_per_run ?? 1000,
      maxRecordsPerRun: cfg.policy.max_records_per_run ?? 50_000,
      anomalyMultiplier: cfg.policy.anomaly_multiplier ?? 5,
    },
  };
}

export async function loadConnectorFile(file: string, env = process.env): Promise<ResolvedConnector> {
  const text = await readFile(file, "utf8");
  const res = validateConfigText(text, { env });
  if (!res.ok || !res.config) throw new ConfigError(file, res.errors);
  return resolveConnector(res.config, res.configHash);
}
