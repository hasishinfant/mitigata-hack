// IP addresses and CIDR ranges, for IP allow-lists and foreign-IP detection rules. IPv4 and IPv6.
// Entries may be comma-separated, so one `${env.IX_EGRESS_IPS}` can expand to several ranges.
import { BlockList, isIP } from "node:net";

export type IpRanges = { list: BlockList; entries: string[]; any: boolean };

/** Split comma-separated entries; returns the normalised entries and any invalid ones. */
export function splitRanges(values: readonly string[]): { entries: string[]; invalid: string[] } {
  const entries: string[] = [];
  const invalid: string[] = [];
  for (const v of values)
    for (const raw of v.split(",")) {
      const e = raw.trim();
      if (!e) continue;
      const [ip, bits] = e.split("/");
      const fam = isIP(ip ?? "");
      const max = fam === 6 ? 128 : 32;
      const ok = fam !== 0 && (bits === undefined || (/^\d{1,3}$/.test(bits) && Number(bits) <= max));
      (ok ? entries : invalid).push(e);
    }
  return { entries, invalid };
}

export function parseRanges(values: readonly string[]): IpRanges {
  const { entries } = splitRanges(values);
  const list = new BlockList();
  let any = false;
  for (const e of entries) {
    const [ip, bits] = e.split("/") as [string, string | undefined];
    const fam = isIP(ip) === 6 ? "ipv6" : "ipv4";
    if (bits === undefined) list.addAddress(ip, fam);
    else {
      list.addSubnet(ip, Number(bits), fam);
      if (Number(bits) === 0) any = true;
    }
  }
  return { list, entries, any };
}

export function ipIn(r: IpRanges, ip: string): boolean {
  const fam = isIP(ip);
  if (!fam) return false;
  return r.list.check(ip, fam === 6 ? "ipv6" : "ipv4");
}
