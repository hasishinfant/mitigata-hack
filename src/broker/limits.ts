// Bounded denial logging for the broker's own endpoints.
// A flood of rejected requests writes a bounded number of ledger rows. The first denial in each window is written
// as is; the rest are counted and written as one summary row when the window ends (or the broker shuts down).
// Every row carries the number of requests it stands for in the ledger's `records` column (1, or N for a summary),
// inside the hash chain, so counts stay exact and tamper-evident: count denied requests with sum(records), not count(*).
// Limit: the counter is in memory. If the broker crashes (no clean shutdown), denials suppressed in the open
// window are lost; the first denial of that window is always on the ledger.
import type { AuditEntry } from "./ledger.ts";

export class DenialLog {
  private readonly windows = new Map<string, { start: number; suppressed: number; entry: AuditEntry }>();
  private readonly audit: (e: AuditEntry) => Promise<void>;
  private readonly windowMs: number;
  private readonly now: () => number;
  private timer: NodeJS.Timeout | undefined;

  constructor(audit: (e: AuditEntry) => Promise<void>, windowMs = 60_000, now: () => number = Date.now) {
    this.audit = audit;
    this.windowMs = windowMs;
    this.now = now;
  }

  /** Record a denial under a low-cardinality key: "admin-token", or one key per existing connector. */
  async record(key: string, entry: AuditEntry): Promise<void> {
    const t = this.now();
    const w = this.windows.get(key);
    if (w && t - w.start < this.windowMs) {
      w.suppressed++;
      this.arm();
      return;
    }
    if (w?.suppressed) await this.summary(w); // only when something was suppressed: no records = 0 rows
    this.windows.set(key, { start: t, suppressed: 0, entry });
    await this.audit({ ...entry, records: 1 });
  }

  /** Write a summary row for every window that suppressed denials. Called on a timer and on close. */
  async flush(): Promise<void> {
    for (const [key, w] of this.windows) {
      if (w.suppressed) await this.summary(w);
      this.windows.delete(key);
    }
  }

  close(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    return this.flush();
  }

  private async summary(w: { suppressed: number; entry: AuditEntry }): Promise<void> {
    const n = w.suppressed;
    w.suppressed = 0;
    await this.audit({ ...w.entry, records: n, decision: `${w.entry.decision} (and ${n} more within ${Math.round(this.windowMs / 1000)} s, summarised)` });
  }

  private arm(): void {
    if (this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.flush().catch(() => {});
    }, this.windowMs);
    this.timer.unref();
  }
}
