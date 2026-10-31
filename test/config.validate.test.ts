import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { validateConfigText } from "../src/config/validate.ts";

const env = { GITHUB_ORG: "acme", GITHUB_REPO: "web", OKTA_ORG: "integrator-123" };
const fx = (name: string) => readFileSync(join(import.meta.dirname, "fixtures/configs", name), "utf8");
const v = (name: string) => validateConfigText(fx(name), { env });
const first = (name: string) => v(name).errors[0]!;

describe("sample connectors", () => {
  const dir = join(import.meta.dirname, "../connectors");
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".yaml"))) {
    it(`${f} validates`, () => {
      const res = validateConfigText(readFileSync(join(dir, f), "utf8"), { env });
      expect(res.errors).toEqual([]);
      expect(res.ok).toBe(true);
    });
  }
  it("CISA KEV live-demo config validates unchanged", () => {
    expect(v("cisa-kev.yaml").errors).toEqual([]);
  });
});

describe("broken configs fail with line and path", () => {
  it("typo: unknown key with suggestion", () => {
    const e = first("bad-typo.yaml");
    expect(e.path).toBe("streams[0].mapping.timestamp.trasform");
    expect(e.line).toBe(17);
    expect(e.message).toContain('did you mean "transform"');
  });
  it("non-GET method refused in request and policy", () => {
    const res = v("bad-delete.yaml");
    expect(res.ok).toBe(false);
    const paths = res.errors.map((e) => e.path);
    expect(paths).toContain("streams[0].request.method");
    expect(paths).toContain("policy.methods[1]");
    expect(res.errors.find((e) => e.path === "streams[0].request.method")!.line).toBe(10);
  });
  it("host outside policy", () => {
    const e = first("bad-host.yaml");
    expect(e.path).toBe("connection.base_url");
    expect(e.line).toBe(5);
    expect(e.message).toContain("outside policy.allowed_hosts");
  });
  it("literal secret rejected, and the secret is not echoed", () => {
    const res = v("bad-secret.yaml");
    const msgs = res.errors.map((e) => e.message).join("\n");
    expect(msgs).toContain("literal secret (github_token)");
    expect(msgs).not.toContain("ghp_");
  });
  it("missing secret ref", () => {
    const e = first("bad-missing-ref.yaml");
    expect(e.path).toBe("connection.auth.secret_ref");
    expect(e.message).toContain('missing required key "secret_ref"');
  });
  it("YAML duplicate key", () => {
    const e = first("bad-yaml.yaml");
    expect(e.path).toBe("(yaml)");
    expect(e.line).toBe(10);
  });
  it("unknown pagination type with suggestion", () => {
    const e = first("bad-pagination.yaml");
    expect(e.path).toBe("streams[0].pagination.type");
    expect(e.message).toContain('did you mean "none"');
  });
});

describe("rules", () => {
  const base = fx("cisa-kev.yaml");
  const run = (src: string, e: Record<string, string> = env) => validateConfigText(src, { env: e });
  it("unknown mapping field for entity", () => {
    const res = run(base.replace("description:", "descriptoin:"));
    expect(res.errors[0]!.message).toContain('did you mean "description"');
  });
  it("bad path syntax", () => {
    const res = run(base.replace("path: cveID", "path: cve..ID"));
    expect(res.errors[0]!.path).toBe("streams[0].mapping.id.path");
  });
  it("severity const outside enum", () => {
    expect(run(base.replace("const: critical", "const: severe")).errors[0]!.path).toBe("streams[0].mapping.severity.const");
  });
  it("env interpolation: missing var and secret-looking var", () => {
    const src = base.replace("https://www.cisa.gov", "https://${env.CISA_HOST}");
    expect(run(src, {}).errors[0]!.message).toBe("env var CISA_HOST is not set");
    const src2 = base.replace("https://www.cisa.gov", "https://${env.GITHUB_TOKEN}");
    expect(run(src2, { GITHUB_TOKEN: "x" }).errors[0]!.message).toContain("looks like a secret");
  });
  it("credential header in request.headers", () => {
    const src = base.replace("request: { method: GET,", "request: { headers: { Authorization: x }, method: GET,");
    expect(run(src).errors[0]!.message).toContain("carries credentials");
  });
  it("YAML aliases and tags are refused", () => {
    expect(run(base.replace("tenant: demo", "tenant: !!str demo")).errors[0]!.message).toContain("tag");
    expect(run(`x: &a 1\ny: *a\n`).errors[0]!.message).toContain("aliases");
  });
  it("forbidden OAuth scope", () => {
    const src = readFileSync(join(import.meta.dirname, "../connectors/okta-users.yaml"), "utf8").replace(
      "scopes: [okta.users.read]", "scopes: [okta.users.read, okta.users.manage]");
    const e = run(src).errors[0]!;
    expect(e.path).toBe("connection.auth.scopes[1]");
    expect(e.message).toContain("forbid_scopes");
  });
});
