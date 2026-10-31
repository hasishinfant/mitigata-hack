// Secret scanner for raw payloads, quarantine rows and config files.
// Replaces matches with [REDACTED:<kind>].

export const SECRET_PATTERNS: readonly { kind: string; re: RegExp }[] = [
  { kind: "private_key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
  { kind: "aws_access_key", re: /AKIA[0-9A-Z]{16}/g },
  { kind: "github_pat", re: /github_pat_[A-Za-z0-9_]{20,}/g },
  { kind: "github_token", re: /ghp_[A-Za-z0-9]{36}/g },
  { kind: "slack_token", re: /xox[baprs]-[A-Za-z0-9-]+/g },
  { kind: "jwt", re: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
  { kind: "okta_ssws", re: /SSWS [A-Za-z0-9_-]{20,}/g },
];

export function findSecrets(text: string): string[] {
  const kinds: string[] = [];
  for (const { kind, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(text)) kinds.push(kind);
    re.lastIndex = 0;
  }
  return kinds;
}

export function redactString(text: string): string {
  let out = text;
  for (const { kind, re } of SECRET_PATTERNS) out = out.replace(re, `[REDACTED:${kind}]`);
  return out;
}

/** Deep-redact any JSON value. Keys are scanned too. */
export function redactValue<T>(value: T): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return redactString(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) out[redactString(k)] = walk(x);
      return out;
    }
    return v;
  };
  return walk(value) as T;
}
