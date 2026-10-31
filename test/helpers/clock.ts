import type { Clock } from "../../src/broker/retry.ts";

/** Fake clock: sleeps return immediately but advance time, and are recorded with their reason. */
export function fakeClock() {
  let t = Date.now();
  const sleeps: { ms: number; reason: string }[] = [];
  const clock: Clock = {
    now: () => t,
    sleep: async (ms, reason) => {
      sleeps.push({ ms, reason });
      t += ms;
    },
  };
  const waits = (reason: string) => sleeps.filter((s) => s.reason === reason).map((s) => s.ms);
  return { clock, sleeps, waits };
}
