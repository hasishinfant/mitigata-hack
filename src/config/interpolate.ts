// `${env.NAME}` interpolation for NON-secret values only.
// Rejected: inside any *_ref key, anywhere under connection.auth, and env names that look secret.

export type InterpIssue = { path: (string | number)[]; message: string };

const TOKEN_RE = /\$\{([^}]*)\}/g;
const SECRET_NAME_RE = /(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|API_?KEY|CREDENTIAL|_PAT$|^PAT_)/i;

export function interpolate(
  value: unknown,
  env: Record<string, string | undefined>,
): { value: unknown; issues: InterpIssue[] } {
  const issues: InterpIssue[] = [];
  const walk = (v: unknown, path: (string | number)[]): unknown => {
    if (typeof v === "string") return interpString(v, path);
    if (Array.isArray(v)) return v.map((x, i) => walk(x, [...path, i]));
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) out[k] = walk(x, [...path, k]);
      return out;
    }
    return v;
  };
  const interpString = (s: string, path: (string | number)[]): string => {
    if (!s.includes("${")) return s;
    const key = String(path[path.length - 1] ?? "");
    const underAuth = path[0] === "connection" && path[1] === "auth";
    if (key.endsWith("_ref") || underAuth) {
      issues.push({ path, message: "${...} interpolation is not allowed here; secrets go only through *_ref" });
      return s;
    }
    return s.replace(TOKEN_RE, (whole, expr: string) => {
      const m = /^env\.([A-Z][A-Z0-9_]*)$/.exec(expr.trim());
      if (!m) {
        issues.push({ path, message: `bad interpolation ${whole}; only \${env.NAME} with an UPPER_CASE name is supported` });
        return whole;
      }
      const name = m[1]!;
      if (SECRET_NAME_RE.test(name)) {
        issues.push({ path, message: `env var ${name} looks like a secret; store it with "ix secret set" and use a *_ref` });
        return whole;
      }
      const val = env[name];
      if (val === undefined || val === "") {
        issues.push({ path, message: `env var ${name} is not set` });
        return whole;
      }
      return val;
    });
  };
  return { value: walk(value, []), issues };
}
