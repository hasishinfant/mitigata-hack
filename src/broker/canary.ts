// Credential canaries: decoy secrets stored like real ones. They don't prevent theft; they make it loud.
// A decoy value carries a tag: the last 10 base62 characters are an HMAC (keyed from the master key) of everything
// before them. Without the master key a decoy is indistinguishable from a real secret, in the database (where it's
// encrypted like any other) and in plain text. The broker refuses to ever use one, and raises an alarm when:
//   - anything inside the hub tries to use it (a config or request referencing the decoy ref);
//   - it is used outside the hub: URL decoys point back at the hub's canary listener (/hooks/... on the API).
// Limit: a decoy API key tried directly against a real provider is only detected if that provider tells us
// (e.g. its own audit log); URL decoys and in-hub use are always detected.
import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const TAG_LEN = 10;
const BODY_LEN = 30;

export function canaryKey(masterKey: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", masterKey, Buffer.alloc(0), "ix-canary-v1", 32));
}

function base62(buf: Buffer, len: number): string {
  let n = BigInt(`0x${buf.toString("hex")}`);
  let s = "";
  while (s.length < len) {
    s += B62[Number(n % 62n)];
    n /= 62n;
  }
  return s;
}

const tagOf = (key: Buffer, s: string) => base62(createHmac("sha256", key).update(s).digest(), TAG_LEN);

/** A decoy token: optional prefix (e.g. "ghp_", "sk_live_") + random body + tag. */
export function makeCanary(key: Buffer, prefix = ""): string {
  const body = prefix + base62(randomBytes(32), BODY_LEN);
  return body + tagOf(key, body);
}

/** A decoy webhook URL that points at the hub's canary listener. */
export function makeCanaryUrl(key: Buffer, baseUrl: string): string {
  const t = makeCanary(key);
  return `${baseUrl.replace(/\/$/, "")}/hooks/services/T${t.slice(0, 9)}/B${t.slice(9, 20)}/${t}`;
}

function isTagged(key: Buffer, token: string): boolean {
  if (token.length < BODY_LEN + TAG_LEN) return false;
  const want = Buffer.from(tagOf(key, token.slice(0, -TAG_LEN)));
  const got = Buffer.from(token.slice(-TAG_LEN));
  return want.length === got.length && timingSafeEqual(want, got);
}

/** Does this value (a secret, a URL, a header, any text) contain a decoy? */
export function containsCanary(key: Buffer, value: string): boolean {
  for (const m of value.matchAll(/[A-Za-z0-9_]{40,}/g)) {
    const t = m[0];
    // The tag covers everything before it, including a prefix; try each start so a prefix glued to text still matches.
    if (isTagged(key, t)) return true;
    for (let i = 1; i <= Math.min(16, t.length - BODY_LEN - TAG_LEN); i++) if (isTagged(key, t.slice(i))) return true;
  }
  return false;
}
