// Scope assessment: granted vs expected vs forbidden. Patterns support `*` wildcards (e.g. "okta.*.manage").

export const WRITE_SCOPE_RE = /(manage|write|admin|delete|:all$|^repo$)/i;

const globToRe = (glob: string) => new RegExp(`^${glob.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");

export type ScopeAssessment = {
  expected: string[];
  granted: string[] | null; // null = provider did not report scopes
  extra: string[]; // granted but not expected
  missing: string[]; // expected but not granted
  forbidden: string[]; // granted and matching forbid_scopes
  writeLike: string[]; // granted, not expected, and looks like write/admin
};

export function assessScopes(granted: string[] | null | undefined, expected: string[] = [], forbid: string[] = []): ScopeAssessment {
  if (!granted) return { expected, granted: null, extra: [], missing: [], forbidden: [], writeLike: [] };
  const extra = granted.filter((g) => !expected.includes(g));
  return {
    expected,
    granted,
    extra,
    missing: expected.filter((e) => !granted.includes(e)),
    forbidden: granted.filter((g) => forbid.some((f) => globToRe(f).test(g))),
    writeLike: extra.filter((g) => WRITE_SCOPE_RE.test(g)),
  };
}
