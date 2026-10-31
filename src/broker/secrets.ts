// Secret sources. Phase 2 reads IX_SECRET_<REF> from the environment of the broker process only.
// Phase 6 replaces this with the AES-256-GCM envelope-encrypted store.
import type { SecretSource } from "./types.ts";

export function envSecretSource(env: Record<string, string | undefined> = process.env): SecretSource {
  return {
    async get(_tenant, ref) {
      return env[`IX_SECRET_${ref.toUpperCase()}`] || undefined;
    },
  };
}
