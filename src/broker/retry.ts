// Retry / backoff / rate-limit helpers. Pure functions plus an injectable clock so tests never sleep.

export type Clock = { now(): number; sleep(ms: number, reason: "backoff" | "rate_limit" | "throttle"): Promise<void> };
export const realClock: Clock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

const RETRYABLE_STATUS = new Set([408, 425, 500, 502, 503, 504]);

export type ResponseClass = "ok" | "rate_limited" | "retryable" | "final";

export function classifyResponse(status: number, headers: Record<string, string>): ResponseClass {
  if (status >= 200 && status < 300) return "ok";
  if (status === 429) return "rate_limited";
  if (status === 403 && headers["x-ratelimit-remaining"] === "0") return "rate_limited"; // provider signals an exhausted quota via 403
  if (RETRYABLE_STATUS.has(status)) return "retryable";
  return "final";
}

/** base * 2^attempt with ±10% jitter: 1 s, 2 s, 4 s for base 1 s. */
export function backoffMs(attempt: number, baseMs: number, jitter: boolean, random: () => number = Math.random): number {
  const d = baseMs * 2 ** attempt;
  return jitter ? Math.round(d * (0.9 + 0.2 * random())) : d;
}

/** How long the provider asked us to wait, from Retry-After (seconds or HTTP date) or x-ratelimit-reset (epoch s). */
export function providerWaitMs(headers: Record<string, string>, now: number): number | undefined {
  const ra = headers["retry-after"]?.trim();
  if (ra) {
    if (/^\d+(\.\d+)?$/.test(ra)) return Math.round(Number(ra) * 1000);
    const at = Date.parse(ra);
    if (Number.isFinite(at)) return Math.max(0, at - now);
  }
  const reset = headers["x-ratelimit-reset"]?.trim();
  if (reset && /^\d+$/.test(reset)) return Math.max(0, Number(reset) * 1000 - now);
  return undefined;
}

/** Per-connector token bucket. Burst = one second's worth of requests (min 1). */
export class TokenBucket {
  readonly rpm: number;
  private tokens: number;
  private last: number;
  private readonly capacity: number;
  private readonly perMs: number;

  constructor(rpm: number, now: number) {
    this.rpm = rpm;
    this.capacity = Math.max(1, Math.ceil(rpm / 60));
    this.perMs = rpm / 60_000;
    this.tokens = this.capacity;
    this.last = now;
  }

  /** Take one token, sleeping if needed. Returns ms waited. */
  async take(clock: Clock): Promise<number> {
    this.refill(clock.now());
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return 0;
    }
    const wait = Math.ceil((1 - this.tokens) / this.perMs);
    await clock.sleep(wait, "throttle");
    this.refill(clock.now());
    this.tokens = Math.max(0, this.tokens - 1);
    return wait;
  }

  private refill(now: number): void {
    this.tokens = Math.min(this.capacity, this.tokens + (now - this.last) * this.perMs);
    this.last = now;
  }
}
