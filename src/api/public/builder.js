// Connector builder (B-5): a form that generates the connector YAML live, validates it as you type,
// and registers/tests/runs it with a live output log. Also the "Remove connector" dialog.
// Uses $, el, api, tokenInput and refresh from app.js. All values rendered with textContent only.
"use strict";

const ENTITY_FIELDS = {
  user: ["id", "name", "email", "status", "last_login"],
  device: ["id", "hostname", "ip", "os", "owner", "last_seen"],
  event: ["id", "type", "severity", "timestamp", "description"],
};
const DATE_FIELDS = new Set(["last_login", "last_seen", "timestamp"]);
const TRANSFORMS = ["", "to_iso8601", "from_epoch_ms", "from_epoch_s", "lowercase", "uppercase", "trim", "to_number", "first", "cvss_to_severity"];

const TEMPLATES = {
  blank: { tenant: "demo", auth: "none", entity: "event", stream: "main", pagination: "none", every: "1h", mapping: {} },
  cisa: {
    id: "cisa-kev", source: "cisa_kev", tenant: "demo", base_url: "https://www.cisa.gov", auth: "none",
    entity: "event", stream: "kev", path: "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    records_path: "vulnerabilities[*]", pagination: "none", every: "24h",
    mapping: {
      id: { v: "cveID", req: true }, type: { v: "=known_exploited_vulnerability" }, severity: { v: "=critical" },
      timestamp: { v: "dateAdded", t: "to_iso8601" }, description: { v: "vulnerabilityName" },
    },
    attributes: "dueDate, knownRansomwareCampaignUse, requiredAction",
  },
  github: {
    id: "github-org-members", source: "github", tenant: "demo", base_url: "https://api.github.com", auth: "bearer",
    entity: "user", stream: "members", path: "/orgs/YOUR_ORG/members", params: "per_page=100", records_path: "$",
    pagination: "link_header", every: "1h",
    mapping: { id: { v: "id", req: true }, name: { v: "login", req: true }, status: { v: "=active" } },
    attributes: "login, site_admin",
  },
  nvd: {
    id: "nvd-recent", source: "nvd", tenant: "demo", base_url: "https://services.nvd.nist.gov", auth: "api_key",
    key_in: "header", key_name: "apiKey", entity: "event", stream: "cves", path: "/rest/json/cves/2.0",
    records_path: "vulnerabilities[*]", pagination: "offset", offset_param: "startIndex", limit_param: "resultsPerPage",
    limit: "2000", total_path: "totalResults", every: "6h",
    mapping: {
      id: { v: "cve.id", req: true }, type: { v: "=vulnerability" },
      severity: { v: "cve.metrics.cvssMetricV31[0].cvssData.baseScore", t: "cvss_to_severity" },
      timestamp: { v: "cve.lastModified", t: "to_iso8601", req: true }, description: { v: "cve.descriptions[0].value" },
    },
    attributes: "cve.published, cve.vulnStatus",
  },
};

const form = $("b-form");
const yamlBox = $("b-yaml");
let manual = false; // user edited the YAML directly
let lastValid = null;
let registeredId = null;

// ---------- small helpers ----------
const f = (name) => form.elements.namedItem(name);
const val = (name) => (f(name)?.value ?? "").trim();
const slugRef = (id, suffix) => {
  let s = (id || "connector").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  if (!/^[a-z]/.test(s)) s = `c_${s}`;
  return `${s}_${suffix}`.slice(0, 64);
};
function log(line, cls) {
  const box = $("b-log");
  const row = el("div", cls ? { class: cls } : {}, `${new Date().toLocaleTimeString()}  ${line}`);
  box.append(row);
  box.scrollTop = box.scrollHeight;
}
const adminHeaders = (extra = {}) => {
  if (!ensureToken()) throw new Error("admin token needed (IX_ADMIN_TOKEN in .env)");
  return { authorization: `Bearer ${tokenInput.value}`, ...extra };
};

// ---------- YAML emitter (flow style for small maps, quoted when needed) ----------
const RESERVED = /^(true|false|null|yes|no|on|off|~)$/i;
function sc(v) {
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  const s = String(v);
  return /^[A-Za-z0-9_$][A-Za-z0-9_./@$-]*$/.test(s) && !RESERVED.test(s) && !/^\d+(\.\d+)?$/.test(s) ? s : JSON.stringify(s);
}
function flow(v) {
  if (Array.isArray(v)) return `[${v.map(flow).join(", ")}]`;
  if (v && typeof v === "object") return `{ ${Object.entries(v).map(([k, x]) => `${sc(k)}: ${flow(x)}`).join(", ")} }`;
  return sc(v);
}

// ---------- secrets inputs depend on auth type ----------
function secretSpecs() {
  const id = val("id");
  switch (val("auth")) {
    case "api_key": return [{ key: "secret_ref", ref: slugRef(id, "key"), label: "API key" }];
    case "bearer": return [{ key: "secret_ref", ref: slugRef(id, "token"), label: "Bearer token" }];
    case "basic": return [
      { key: "username_ref", ref: slugRef(id, "user"), label: "Username" },
      { key: "password_ref", ref: slugRef(id, "password"), label: "Password / API token" },
    ];
    case "oauth2_client_credentials": return [
      { key: "client_id_ref", ref: slugRef(id, "client_id"), label: "Client ID" },
      { key: "client_secret_ref", ref: slugRef(id, "client_secret"), label: "Client secret" },
    ];
    default: return [];
  }
}
function renderSecrets() {
  const box = $("b-secrets");
  const keep = Object.fromEntries([...box.querySelectorAll("input")].map((i) => [i.dataset.ref, i.value]));
  box.replaceChildren(...secretSpecs().map((s) =>
    el("label", {}, `${s.label} → stored as secret "${s.ref}"`,
      el("input", { type: "password", "data-ref": s.ref, placeholder: "leave empty to keep the stored value", value: keep[s.ref] ?? "" }))));
}

// ---------- mapping rows depend on entity ----------
function renderMapping(preset) {
  const box = $("b-mapping");
  const current = {};
  for (const row of box.querySelectorAll(".b-map-row")) {
    current[row.dataset.field] = { v: row.querySelector("input[type=text]").value, t: row.querySelector("select").value, req: row.querySelector("input[type=checkbox]").checked };
  }
  const src = preset ?? current;
  box.replaceChildren(...ENTITY_FIELDS[val("entity") || "event"].map((field) => {
    const m = src[field] ?? {};
    const sel = el("select", {}, TRANSFORMS.map((t) => el("option", { value: t }, t || "no transform")));
    sel.value = m.t ?? (DATE_FIELDS.has(field) && m.v ? "to_iso8601" : "");
    const req = el("input", { type: "checkbox", title: "required: records without it go to quarantine" });
    req.checked = field === "id" ? true : Boolean(m.req);
    if (field === "id") req.disabled = true;
    return el("div", { class: "b-map-row", "data-field": field },
      el("span", {}, field),
      el("input", { type: "text", placeholder: field === "id" ? "path to the record's unique id" : "path or =constant", value: m.v ?? "" }),
      sel, req);
  }));
}

// ---------- form -> config object -> YAML ----------
function buildYaml() {
  const id = val("id");
  const lines = ["apiVersion: ix/v1", "kind: Connector"];
  lines.push(`metadata: ${flow({ id, source: val("source") || id.replace(/-/g, "_"), tenant: val("tenant") || "demo" })}`);

  const auth = { type: val("auth") || "none" };
  if (auth.type === "api_key") Object.assign(auth, { in: val("key_in") || "header", name: val("key_name") || "apiKey" }, f("key_prefix").value ? { prefix: f("key_prefix").value } : {});
  if (auth.type === "oauth2_client_credentials") {
    Object.assign(auth, { token_url: val("token_url") || "/oauth2/v1/token" });
  }
  for (const s of secretSpecs()) auth[s.key] = s.ref;
  if (auth.type === "oauth2_client_credentials") {
    auth.client_auth = val("client_auth") || "client_secret_basic";
    if (val("scopes")) auth.scopes = val("scopes").split(/\s+/);
  }
  lines.push("connection:", `  base_url: ${sc(val("base_url"))}`, `  auth: ${flow(auth)}`);

  const request = { method: "GET", path: val("path") || "/" };
  const params = {};
  for (const ln of (f("params").value || "").split("\n")) {
    const i = ln.indexOf("=");
    if (i > 0) params[ln.slice(0, i).trim()] = /^\d+$/.test(ln.slice(i + 1).trim()) ? Number(ln.slice(i + 1).trim()) : ln.slice(i + 1).trim();
  }
  if (Object.keys(params).length) request.params = params;

  const p = val("pagination") || "none";
  const pg = { type: p };
  const num = (n) => (/^\d+$/.test(val(n)) ? Number(val(n)) : val(n));
  if (p === "offset") Object.assign(pg, { offset_param: val("offset_param"), limit_param: val("limit_param"), limit: num("limit") || 100 }, val("total_path") ? { total_path: val("total_path") } : {});
  if (p === "page_number") Object.assign(pg, { page_param: val("page_param"), size_param: val("size_param"), size: num("size") || 100 });
  if (p === "cursor") Object.assign(pg, { token_path: val("token_path"), token_param: val("token_param") }, val("is_last_path") ? { stop_when: "is_last_path", is_last_path: val("is_last_path") } : {});
  if (p === "body_link") pg.next_path = val("next_path");

  lines.push("streams:", `  - name: ${sc(val("stream") || "main")}`, `    entity: ${val("entity") || "event"}`, `    request: ${flow(request)}`);
  lines.push(`    records_path: ${sc(val("records_path") || "$")}`, `    pagination: ${flow(pg)}`, "    mapping:");
  for (const row of $("b-mapping").querySelectorAll(".b-map-row")) {
    const v = row.querySelector("input[type=text]").value.trim();
    if (!v) continue;
    const spec = v.startsWith("=") ? { const: v.slice(1) } : { path: v };
    const t = row.querySelector("select").value;
    if (t && !spec.const) spec.transform = t;
    if (row.querySelector("input[type=checkbox]").checked && !spec.const) spec.required = true;
    lines.push(`      ${row.dataset.field}: ${flow(spec)}`);
  }
  const attrs = val("attributes").split(",").map((x) => x.trim()).filter(Boolean);
  if (attrs.length) lines.push(`      attributes: ${flow({ pick: attrs })}`);

  lines.push(`schedule: ${flow({ every: val("every") || "1h" })}`);
  let host = val("allowed_hosts");
  if (!host) try { host = new URL(val("base_url")).hostname; } catch { host = ""; }
  lines.push(`policy: ${flow({ allowed_hosts: host.split(/[\s,]+/).filter(Boolean), allowed_paths: [request.path], methods: ["GET"] })}`);
  if (auth.type !== "none") lines.push(`credential: ${flow({ max_age_days: 90, idle_disable_days: 14 })}`);
  return lines.join("\n") + "\n";
}

// ---------- show/hide auth + pagination groups ----------
function syncGroups() {
  for (const g of form.querySelectorAll("[data-auth]")) g.classList.toggle("hidden", g.dataset.auth !== val("auth"));
  for (const g of form.querySelectorAll("[data-page]")) g.classList.toggle("hidden", g.dataset.page !== val("pagination"));
  $("b-test").disabled = val("auth") !== "none";
}

// ---------- live validation ----------
let vTimer;
function scheduleValidate() {
  clearTimeout(vTimer);
  vTimer = setTimeout(validateNow, 400);
}
async function validateNow() {
  const text = yamlBox.value;
  if (!text.trim()) return;
  try {
    const r = await api("/v1/configs/validate", { method: "POST", headers: { "content-type": "text/yaml" }, body: text });
    lastValid = r.ok;
    $("b-valid").textContent = r.ok ? `✔ valid${r.warnings.length ? ` · ${r.warnings.length} warning(s)` : ""}` : `✖ ${r.errors.length} error(s)`;
    $("b-valid").className = r.ok ? "ok" : "bad";
    $("b-issues").replaceChildren(...[...r.errors, ...r.warnings].map((i) =>
      el("div", { class: `issue issue-${i.severity}` }, `line ${i.line}:${i.col}  ${i.path}: ${i.message}`)));
  } catch (e) {
    $("b-valid").textContent = `validation unavailable: ${e.message}`;
  }
}

function regenerate() {
  syncGroups();
  if (!manual) yamlBox.value = buildYaml();
  scheduleValidate();
}

function applyTemplate(name) {
  const t = TEMPLATES[name];
  form.reset();
  for (const [k, v] of Object.entries(t)) if (k !== "mapping" && f(k)) f(k).value = v;
  manual = false;
  syncGroups();
  renderSecrets();
  renderMapping(t.mapping);
  regenerate();
}

form.addEventListener("input", (e) => {
  if (e.target.name === "auth" || e.target.name === "id") renderSecrets();
  if (e.target.name === "entity") renderMapping();
  regenerate();
});
form.addEventListener("change", (e) => {
  if (e.target.name === "auth") renderSecrets();
  if (e.target.name === "entity") renderMapping();
  regenerate();
});
yamlBox.addEventListener("input", () => {
  manual = true;
  scheduleValidate();
});
$("b-template").addEventListener("change", (e) => applyTemplate(e.target.value));

// ---------- actions ----------
function logTest(t) {
  for (const s of t.streams) {
    const head = `stream ${s.stream}: ${s.status ? `HTTP ${s.status} in ${s.durationMs} ms, ` : ""}${s.recordsOnPage ?? 0} records on first page${s.hasMorePages ? " (more pages)" : ""}`;
    log(head, s.ok ? "ok" : "bad");
    if (s.error) log(`  ${s.error}`, "bad");
    if (s.warning) log(`  ${s.warning}`);
    for (const smp of s.samples) {
      if (smp.result.ok) log(`  ✔ ${JSON.stringify({ id: smp.result.record.sourceId, ...smp.result.record.fields }).slice(0, 220)}`);
      else log(`  ✖ would be quarantined: ${smp.result.errors.join("; ")}`, "bad");
    }
  }
  if (t.credential?.grantedScopes) log(`granted scopes: ${t.credential.grantedScopes.join(" ")}`);
}

$("b-test").addEventListener("click", async () => {
  try {
    await validateNow();
    if (!lastValid) return log("✖ fix the config errors first", "bad");
    log("testing (live call through the broker, nothing is written)…");
    logTest(await api("/v1/configs/test", { method: "POST", headers: adminHeaders({ "content-type": "text/yaml" }), body: yamlBox.value }));
  } catch (e) {
    log(`✖ ${e.message}`, "bad");
  }
});

$("b-register").addEventListener("click", async () => {
  const btn = $("b-register");
  btn.disabled = true;
  try {
    await validateNow();
    if (!lastValid) return log("✖ fix the config errors first", "bad");
    const yaml = yamlBox.value;
    const id = /^\s*metadata:.*\bid:\s*"?([a-z0-9-]+)/m.exec(yaml)?.[1] || val("id");
    const tenant = val("tenant") || "demo";
    for (const input of $("b-secrets").querySelectorAll("input")) {
      if (!input.value) {
        log(`secret "${input.dataset.ref}": no value entered, using the stored one if it exists`);
        continue;
      }
      const r = await api(`/v1/secrets/${encodeURIComponent(input.dataset.ref)}?tenant=${encodeURIComponent(tenant)}`, {
        method: "PUT", headers: adminHeaders({ "content-type": "application/json" }), body: JSON.stringify({ value: input.value }),
      });
      input.value = "";
      log(`✔ secret "${r.ref}" stored encrypted in the broker (${r.chars} chars)`, "ok");
    }
    let reg;
    try {
      reg = await api("/v1/connectors", { method: "POST", headers: adminHeaders({ "content-type": "text/yaml" }), body: yaml });
    } catch (e) {
      if (!/already exists/.test(e.message)) throw e;
      reg = await api(`/v1/connectors/${encodeURIComponent(id)}`, { method: "PUT", headers: adminHeaders({ "content-type": "text/yaml" }), body: yaml });
    }
    registeredId = reg.id;
    log(`✔ ${reg.id} v${reg.version} ${reg.changed ? "registered and signed by the broker" : "unchanged"}`, "ok");
    log("testing (auth + first page + 3 mapped records)…");
    logTest(await api(`/v1/connectors/${encodeURIComponent(reg.id)}/test`, { method: "POST", headers: adminHeaders() }));
    $("b-run").disabled = false;
    refresh();
  } catch (e) {
    log(`✖ ${e.message}`, "bad");
  } finally {
    btn.disabled = false;
  }
});

$("b-run").addEventListener("click", async () => {
  if (!registeredId) return;
  const id = registeredId;
  const since = Date.now() - 2000;
  try {
    const q = await api(`/v1/connectors/${encodeURIComponent(id)}/runs`, { method: "POST", headers: adminHeaders() });
    log(q.queued ? `run queued for ${id}, waiting for the worker…` : `a run is already queued or running for ${id}, watching it…`);
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const { runs } = await api(`/v1/connectors/${encodeURIComponent(id)}/runs?limit=5`);
      const run = runs.find((r) => Date.parse(r.started_at) >= since);
      if (!run) continue;
      if (run.status === "running") {
        if (i % 3 === 0) log(`  running… ${run.requests} request(s), ${run.records_ok} records so far`);
        continue;
      }
      const good = ["success", "partial"].includes(run.status);
      log(`${good ? "✔" : "✖"} run ${run.status}: ${run.requests} request(s), ${run.records_ok} records stored, ${run.records_quarantined} quarantined${run.last_error ? ` · ${run.last_error}` : ""}`, good ? "ok" : "bad");
      refresh();
      return;
    }
    log("still running after 3 minutes; check the Connectors tab");
  } catch (e) {
    log(`✖ ${e.message}`, "bad");
  }
});

// ---------- remove connector ----------
const removeSelect = $("remove-select");
const syncRemove = () => { $("remove-go").disabled = !removeSelect.value; };
async function loadRemoveList() {
  try {
    const h = await api("/v1/health");
    removeSelect.replaceChildren(el("option", { value: "" }, "choose…"), ...h.connectors.map((c) => el("option", { value: c.id }, `${c.id} (${c.source}, ${c.records_in_store} records)`)));
  } catch (e) {
    $("remove-log").textContent = e.message;
  }
  syncRemove();
}
$("open-remove").addEventListener("click", async () => {
  $("remove-log").textContent = "";
  await loadRemoveList();
  if (!$("remove").open) $("remove").showModal();
});
removeSelect.addEventListener("change", syncRemove);
$("remove-close").addEventListener("click", () => $("remove").close());
$("remove-go").addEventListener("click", async () => {
  const id = removeSelect.value;
  if (!id || !confirm(`Remove ${id}, all its records and its secrets?`)) return;
  try {
    const r = await api(`/v1/connectors/${encodeURIComponent(id)}`, { method: "DELETE", headers: adminHeaders() });
    const lines = [`✔ ${r.id} removed (${r.records} records deleted)`];
    if (r.secrets?.deleted.length) lines.push(`  secrets deleted: ${r.secrets.deleted.join(", ")}`);
    if (r.secrets?.kept_shared.length) lines.push(`  secrets kept (still used by another connector): ${r.secrets.kept_shared.join(", ")}`);
    lines.push("  recorded in the audit ledger");
    $("remove-log").textContent = lines.join("\n");
    refresh();
    await loadRemoveList();
  } catch (e) {
    $("remove-log").textContent = `✖ ${e.message}`;
  }
});

applyTemplate("blank");
