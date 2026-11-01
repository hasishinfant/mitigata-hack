// ix/v1 connector config schema. Structure only; cross-field rules live in validate.ts.
// Every object is strict: unknown keys are errors. No defaults here (see load.ts).
import { z } from "zod";

export const DURATION_RE = /^\d+(ms|s|m|h|d)$/;
const duration = z.string().regex(DURATION_RE, { error: 'duration like "500ms", "20s", "15m", "24h", "7d"' });
const ref = z.string().regex(/^[a-z][a-z0-9_]{1,63}$/, { error: "secret ref: lowercase letters, digits, _ (e.g. github_pat)" });
const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/, { error: "lowercase letters, digits, - (max 63)" });
const posInt = z.number().int().positive();

export const TRANSFORMS = [
  "to_iso8601", "from_epoch_ms", "from_epoch_s", "lowercase", "uppercase",
  "trim", "to_number", "first", "cvss_to_severity",
] as const;
export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export const ENTITY_FIELDS = {
  user: ["id", "name", "email", "status", "last_login", "attributes"],
  device: ["id", "hostname", "ip", "os", "owner", "last_seen", "attributes"],
  event: ["id", "type", "severity", "timestamp", "description", "attributes"],
} as const;
export type Entity = keyof typeof ENTITY_FIELDS;

// ---- auth ----
const AuthNone = z.strictObject({ type: z.literal("none") });
const AuthApiKey = z.strictObject({
  type: z.literal("api_key"),
  in: z.enum(["header", "query"]),
  name: z.string().min(1),
  prefix: z.string().optional(), // e.g. "SSWS " for Okta API tokens
  secret_ref: ref,
});
const AuthBasic = z.strictObject({ type: z.literal("basic"), username_ref: ref, password_ref: ref });
const AuthBearer = z.strictObject({ type: z.literal("bearer"), secret_ref: ref });
const AuthOAuth2 = z.strictObject({
  type: z.literal("oauth2_client_credentials"),
  token_url: z.string().min(1),
  client_id_ref: ref,
  client_auth: z.enum(["client_secret_basic", "client_secret_post", "private_key_jwt"]),
  client_secret_ref: ref.optional(),
  private_key_ref: ref.optional(),
  key_id: z.string().optional(),
  scopes: z.array(z.string().min(1)).optional(),
  audience: z.string().optional(),
  revocation_url: z.string().optional(), // RFC 7009 endpoint: panic revokes cached tokens here
});
export const AuthSchema = z.discriminatedUnion("type", [AuthNone, AuthApiKey, AuthBasic, AuthBearer, AuthOAuth2]);

// ---- pagination ----
const PageLink = z.strictObject({ type: z.literal("link_header"), rel: z.string().optional(), stop_when: z.literal("no_next").optional() });
const PageOffset = z.strictObject({
  type: z.literal("offset"),
  offset_param: z.string().min(1),
  limit_param: z.string().min(1),
  limit: posInt,
  total_path: z.string().min(1).optional(), // without it: stop on a short or empty page
  start: z.number().int().nonnegative().optional(),
});
const PageNumber = z.strictObject({
  type: z.literal("page_number"),
  page_param: z.string().min(1),
  size_param: z.string().min(1),
  size: posInt,
  start: z.number().int().nonnegative().optional(),
  stop_when: z.literal("empty_page").optional(),
});
const PageCursor = z.strictObject({
  type: z.literal("cursor"),
  token_path: z.string().optional(),
  token_header: z.string().optional(),
  token_param: z.string().min(1),
  stop_when: z.enum(["no_token", "is_last_path"]).optional(),
  is_last_path: z.string().optional(),
});
const PageBodyLink = z.strictObject({ type: z.literal("body_link"), next_path: z.string().min(1) }); // next URL inside the JSON body
const PageNone = z.strictObject({ type: z.literal("none") });
export const PaginationSchema = z.discriminatedUnion("type", [PageLink, PageBodyLink, PageOffset, PageNumber, PageCursor, PageNone]);

// ---- mapping ----
const scalar = z.union([z.string(), z.number(), z.boolean(), z.null()]);
// concat items: a bare string is ALWAYS a path; literals must be wrapped as { lit: "..." }.
const ConcatItem = z.union([z.string(), z.strictObject({ lit: z.string() })]);
export const FieldSpecSchema = z.strictObject({
  path: z.union([z.string(), z.array(z.string()).min(1)]).optional(), // array = first non-null wins
  const: scalar.optional(),
  concat: z.array(ConcatItem).min(1).optional(),
  pick: z.array(z.string()).min(1).optional(),
  transform: z.union([z.enum(TRANSFORMS), z.array(z.enum(TRANSFORMS)).min(1)]).optional(),
  map_enum: z.record(z.string(), z.string()).optional(),
  default: scalar.optional(),
  required: z.boolean().optional(),
});

// ---- streams ----
const paramValue = z.union([z.string(), z.number(), z.boolean()]);
export const StreamSchema = z.strictObject({
  name: slug,
  entity: z.enum(["user", "device", "event"]),
  request: z.strictObject({
    // POST only for read-only search endpoints declared in policy.read_only_post
    method: z.enum(["GET", "POST"], { error: "method must be GET (or POST for a search endpoint listed in policy.read_only_post)" }),
    path: z.string().startsWith("/", { error: 'path must start with "/"' }),
    params: z.record(z.string(), paramValue).optional(),
    headers: z.record(z.string(), z.string()).optional(),
    body: z.record(z.string(), z.unknown()).optional(), // JSON body for POST search
    paging_in: z.enum(["query", "body"]).optional(), // where pagination params go (default query)
  }),
  records_path: z.string().optional(),
  pagination: PaginationSchema,
  incremental: z
    .strictObject({
      cursor_field: z.string().min(1),
      param: z.string().min(1),
      template: z.string().includes("{{cursor}}", { error: "template must contain {{cursor}}" }),
      initial: z.string().optional(), // ISO date or relative like "-7d"
      extra_params: z.record(z.string(), z.string()).optional(), // may use {{now}}
    })
    .optional(),
  mapping: z.record(z.string(), FieldSpecSchema),
  // Integrity limits for publication (T7/T8). Over a limit, the sync is held for review instead of published.
  expect: z
    .strictObject({
      max_quarantine_ratio: z.number().min(0).max(1).optional(), // default 0.1
      min_records: z.number().int().nonnegative().optional(), // default 0: an explicit empty result is valid
    })
    .optional(),
});

// ---- top level ----
export const ConnectorSchema = z.strictObject({
  apiVersion: z.literal("ix/v1"),
  kind: z.literal("Connector"),
  metadata: z.strictObject({
    id: slug,
    source: z.string().regex(/^[a-z][a-z0-9_]{0,62}$/, { error: "lowercase letters, digits, _" }),
    tenant: slug,
    owner: z.email().optional(),
  }),
  connection: z.strictObject({ base_url: z.string().min(1), auth: AuthSchema }),
  streams: z.array(StreamSchema).min(1),
  schedule: z.strictObject({ every: duration, jitter: duration.optional() }).optional(),
  reliability: z
    .strictObject({
      timeout: duration.optional(),
      retries: z
        .strictObject({
          max: z.number().int().min(0).max(10).optional(),
          backoff: z.literal("exponential").optional(),
          base: duration.optional(),
          jitter: z.boolean().optional(),
        })
        .optional(),
      rate_limit: z
        .strictObject({
          requests_per_minute: posInt.optional(),
          respect_retry_after: z.boolean().optional(),
          max_wait: duration.optional(),
        })
        .optional(),
      circuit_breaker: z
        .strictObject({ failures_to_open: posInt.optional(), cool_down: duration.optional() })
        .optional(),
    })
    .optional(),
  policy: z.strictObject({
    allowed_hosts: z.array(z.string().min(1)).min(1),
    allowed_paths: z.array(z.string().startsWith("/")).min(1).optional(),
    methods: z
      .array(z.literal("GET", { error: "only GET is allowed in policy.methods (POST is used internally for token_url only)" }))
      .min(1)
      .optional(),
    read_only_post: z.array(z.string().startsWith("/")).optional(), // search endpoints that read via POST
    max_requests_per_run: posInt.optional(),
    max_records_per_run: posInt.optional(),
    anomaly_multiplier: z.number().gt(1).optional(),
  }),
  credential: z
    .strictObject({
      expected_scopes: z.array(z.string()).optional(),
      forbid_scopes: z.array(z.string()).optional(),
      max_age_days: posInt.optional(),
      idle_disable_days: posInt.optional(),
      provider_ip_restriction: z.enum(["yes", "no", "unknown"]).optional(),
      scopes_header: z.string().optional(), // response header listing the token's granted scopes, if the provider sends one
      revocable_by_api: z.boolean().optional(), // can the hub revoke this credential itself (OAuth revocation)?
      revoke_hint: z.string().max(300).optional(), // where a human revokes it, printed by `ix panic`
    })
    .optional(),
  data: z
    .strictObject({
      store_raw: z.boolean().optional(),
      redact_secrets: z.boolean().optional(),
      retention_days: posInt.optional(),
    })
    .optional(),
  alerts: z
    .strictObject({ on_consecutive_failures: posInt.optional(), slack_webhook_ref: ref.optional() })
    .optional(),
});

export type ConnectorConfig = z.infer<typeof ConnectorSchema>;
export type StreamConfig = z.infer<typeof StreamSchema>;
export type FieldSpec = z.infer<typeof FieldSpecSchema>;

export function connectorJsonSchema(): unknown {
  return z.toJSONSchema(ConnectorSchema);
}
