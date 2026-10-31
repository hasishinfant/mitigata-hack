// Pure policy matchers shared by the config validator and (later) the broker's runtime check.
// Paths: exact match, `*` = one path segment, trailing `/**` = any remainder.
// Hosts: exact (case-insensitive), or `*.example.com` = exactly one extra label.

export function hostAllowed(host: string, allowed: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return allowed.some((pattern) => {
    const p = pattern.toLowerCase();
    if (p.startsWith("*.")) {
      const suffix = p.slice(1);
      if (!h.endsWith(suffix)) return false;
      const label = h.slice(0, -suffix.length);
      return label.length > 0 && !label.includes(".");
    }
    return h === p;
  });
}

export function pathAllowed(path: string, allowed: readonly string[]): boolean {
  const clean = path.split("?")[0] ?? "";
  if (clean.includes("..") || clean.includes("//") || /%2e|%2f/i.test(clean)) return false;
  const parts = clean.split("/").filter(Boolean);
  return allowed.some((pattern) => {
    const pp = pattern.split("/").filter(Boolean);
    for (let i = 0; i < pp.length; i++) {
      const seg = pp[i];
      if (seg === "**" && i === pp.length - 1) return parts.length >= i;
      if (i >= parts.length) return false;
      if (seg !== "*" && seg !== parts[i]) return false;
    }
    return pp.length === parts.length;
  });
}

export function methodAllowed(method: string, allowed: readonly string[]): boolean {
  return allowed.map((m) => m.toUpperCase()).includes(method.toUpperCase());
}
