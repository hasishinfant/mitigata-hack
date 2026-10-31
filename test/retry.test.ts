import { describe, expect, it } from "vitest";
import { backoffMs, classifyResponse, providerWaitMs, TokenBucket } from "../src/broker/retry.ts";
import { detectDrift } from "../src/engine/runner.ts";
import { fakeClock } from "./helpers/clock.ts";

describe("retry helpers", () => {
  it("backoff is 1 s, 2 s, 4 s with bounded jitter", () => {
    expect([0, 1, 2].map((a) => backoffMs(a, 1000, false))).toEqual([1000, 2000, 4000]);
    expect([0, 1, 2].map((a) => backoffMs(a, 1000, true, () => 0.5))).toEqual([1000, 2000, 4000]);
    expect(backoffMs(0, 1000, true, () => 0)).toBe(900);
    expect(backoffMs(0, 1000, true, () => 1)).toBe(1100);
  });
  it("classifies responses", () => {
    expect(classifyResponse(200, {})).toBe("ok");
    expect(classifyResponse(429, {})).toBe("rate_limited");
    expect(classifyResponse(403, { "x-ratelimit-remaining": "0" })).toBe("rate_limited");
    expect(classifyResponse(403, {})).toBe("final");
    for (const s of [408, 425, 500, 502, 503, 504]) expect(classifyResponse(s, {})).toBe("retryable");
    for (const s of [400, 401, 404, 422]) expect(classifyResponse(s, {})).toBe("final");
  });
  it("reads Retry-After seconds / HTTP date and x-ratelimit-reset", () => {
    const now = Date.UTC(2026, 0, 1, 0, 0, 0);
    expect(providerWaitMs({ "retry-after": "30" }, now)).toBe(30_000);
    expect(providerWaitMs({ "retry-after": "Thu, 01 Jan 2026 00:00:10 GMT" }, now)).toBe(10_000);
    expect(providerWaitMs({ "x-ratelimit-reset": String(now / 1000 + 5) }, now)).toBe(5_000);
    expect(providerWaitMs({ "retry-after": "Thu, 01 Jan 2025 00:00:10 GMT" }, now)).toBe(0);
    expect(providerWaitMs({}, now)).toBeUndefined();
  });
  it("token bucket throttles to requests_per_minute", async () => {
    const { clock, waits } = fakeClock();
    const b = new TokenBucket(60, clock.now());
    for (let i = 0; i < 4; i++) await b.take(clock);
    expect(waits("throttle")).toEqual([1000, 1000, 1000]);
  });
  it("drift: >= 50 point jump in miss rate", () => {
    const prev = { records: 100, hits: { email: 100, name: 60 } };
    expect(detectDrift(prev, { records: 100, hits: { email: 0, name: 55 } }, ["email", "name"])).toEqual([
      "email missing in 100% of records (was 0%)",
    ]);
    expect(detectDrift(null, { records: 100, hits: {} }, ["email"])).toEqual([]);
    expect(detectDrift(prev, { records: 3, hits: {} }, ["email"])).toEqual([]);
  });
});
