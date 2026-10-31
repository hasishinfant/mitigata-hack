// pino logger to stderr with two layers of protection:
// 1. `redact` for well-known secret-bearing keys,
// 2. a final scrub of every line: currently loaded secret values + token regexes.
import pino from "pino";
import { redactString } from "./mapping/scanner.ts";

const loadedSecrets = new Set<string>();

/** Register a secret value so it is scrubbed from any log line. Short values are ignored (too many false hits). */
export function registerSecretForScrub(value: string): void {
  if (value.length >= 6) loadedSecrets.add(value);
}
export function forgetSecrets(): void {
  loadedSecrets.clear();
}

export function scrub(line: string): string {
  let out = redactString(line);
  for (const s of loadedSecrets) if (out.includes(s)) out = out.split(s).join("[REDACTED:secret]");
  return out;
}

const SECRET_KEYS = ["authorization", "apiKey", "apikey", "key", "token", "password", "client_secret", "private_key", "secret"];

export const log = pino(
  {
    level: process.env.IX_LOG_LEVEL ?? "info",
    base: undefined,
    redact: {
      paths: [...SECRET_KEYS, ...SECRET_KEYS.map((k) => `*.${k}`), ...SECRET_KEYS.map((k) => `headers.${k}`)],
      censor: "[REDACTED]",
    },
    hooks: { streamWrite: scrub },
  },
  pino.destination({ dest: 2, sync: true }),
);
