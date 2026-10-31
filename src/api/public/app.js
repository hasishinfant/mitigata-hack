// IntegrateX dashboard. Plain JS, no build step. Every value from the API is rendered with
// textContent only, never parsed as HTML: provider data and error messages are untrusted.
"use strict";

const $ = (id) => document.getElementById(id);
const tokenInput = $("token");
tokenInput.value = sessionStorage.getItem("ix_admin_token") || "";
tokenInput.addEventListener("change", () => sessionStorage.setItem("ix_admin_token", tokenInput.value));

/** Build an element: el("div", { class: "x", title: "y" }, child, "text", ...). */
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
  return node;
}

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  const abs = Math.abs(s);
  const unit = abs < 60 ? [abs, "s"] : abs < 3600 ? [Math.round(abs / 60), "m"] : abs < 86400 ? [Math.round(abs / 3600), "h"] : [Math.round(abs / 86400), "d"];
  return s >= 0 ? `${unit[0]}${unit[1]} ago` : `in ${unit[0]}${unit[1]}`;
}
const num = (n) => (n === null || n === undefined ? "—" : Number(n).toLocaleString());
const RUN_TO_HEALTH = { success: "healthy", partial: "warning", degraded: "degraded", failed: "failing", auth_failed: "failing", running: "running", paused: "paused" };

// ---------- connectors ----------
function card(c) {
  const lr = c.last_run;
  const meta = el("dl", { class: "meta" },
    el("dt", {}, "Last run"), el("dd", {}, lr ? `${ago(lr.started_at)} · ${lr.status} · ${lr.trigger}` : "never"),
    el("dt", {}, "Records pulled"), el("dd", {}, lr ? `${num(lr.records_pulled)} (last run)` : "—"),
    el("dt", {}, "In store"), el("dd", {}, num(c.records_in_store)),
    el("dt", {}, "Quarantined"), el("dd", {}, num(c.quarantine_total)),
    el("dt", {}, "Schedule"), el("dd", {}, c.schedule_every ? `every ${c.schedule_every} · next ${ago(c.next_run_at)}` : "on demand"),
    lr && (lr.retries || lr.rate_limited_ms) ? [el("dt", {}, "Reliability"), el("dd", {}, `${lr.retries} retries · waited ${(lr.rate_limited_ms / 1000).toFixed(1)}s`)] : null,
  );
  const strip = el("div", { class: "strip", title: "recent runs, newest first" },
    (c.recent_runs || []).map((s) => el("span", { class: `h-${RUN_TO_HEALTH[s] || "never_run"}`, title: s })));
  const runBtn = el("button", { onclick: () => runNow(c.id, runBtn) }, "Run now");
  return el("article", { class: `card h-${c.health}` },
    el("h3", {}, el("span", {}, c.id), el("span", { class: `pill h-${c.health}` }, c.health.replace("_", " "))),
    el("div", { class: "badges" },
      el("span", { class: "badge" }, c.source),
      c.auth_type && el("span", { class: "badge" }, c.auth_type),
      c.entities.map((e) => el("span", { class: "badge" }, e)),
      c.config_version && el("span", { class: "badge" }, `v${c.config_version}`)),
    meta,
    strip,
    c.reason ? el("div", { class: "error", title: c.reason }, c.reason) : null,
    c.last_error && c.last_error !== c.reason ? el("div", { class: "error", title: c.last_error }, c.last_error) : null,
    el("div", { class: "actions" }, runBtn, el("button", { onclick: () => showHistory(c.id) }, "History")),
  );
}

async function refresh() {
  try {
    const h = await api("/v1/health");
    $("summary").replaceChildren(
      el("span", { class: "chip" }, `${h.summary.total} connectors`),
      ...Object.entries(h.summary).filter(([k]) => k !== "total").map(([k, v]) => el("span", { class: `chip` }, `${v} ${k.replace("_", " ")}`)),
    );
    $("cards").replaceChildren(...h.connectors.map(card));
    $("empty").classList.toggle("hidden", h.connectors.length > 0);
    $("updated").textContent = `updated ${new Date(h.generated_at).toLocaleTimeString()}`;
  } catch (e) {
    $("updated").textContent = `API unreachable: ${e.message}`;
  }
}

async function runNow(id, btn) {
  if (!tokenInput.value) {
    tokenInput.focus();
    alert("Enter the admin token (IX_ADMIN_TOKEN) first.");
    return;
  }
  btn.disabled = true;
  try {
    const r = await api(`/v1/connectors/${encodeURIComponent(id)}/runs`, { method: "POST", headers: { authorization: `Bearer ${tokenInput.value}` } });
    btn.textContent = r.queued ? "Queued" : "Already running";
    setTimeout(refresh, 1500);
  } catch (e) {
    alert(`Run failed: ${e.message}`);
  } finally {
    setTimeout(() => { btn.disabled = false; btn.textContent = "Run now"; }, 4000);
  }
}

function table(target, rows, columns) {
  const cols = columns || (rows[0] ? Object.keys(rows[0]) : []);
  target.replaceChildren(
    el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c)))),
    el("tbody", {}, rows.map((r) => el("tr", {}, cols.map((c) => {
      const v = r[c];
      const text = v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
      return el("td", { title: text }, text);
    })))),
  );
}

async function showHistory(id) {
  $("history-title").textContent = `Run history: ${id}`;
  const { runs } = await api(`/v1/connectors/${encodeURIComponent(id)}/runs?limit=50`);
  table($("history-table"), runs, ["started_at", "stream", "status", "trigger", "requests", "records_ok", "records_quarantined", "retries", "rate_limited_ms", "resumed", "last_error"]);
  $("history").showModal();
}
$("history-close").addEventListener("click", () => $("history").close());

// ---------- records ----------
async function loadRecords() {
  const params = new URLSearchParams({ limit: "200" });
  if ($("source").value.trim()) params.set("source", $("source").value.trim());
  try {
    const r = await api(`/v1/records/${$("entity").value}?${params}`);
    table($("records"), r.rows);
    $("records-count").textContent = `${r.rows.length} of ${num(r.total)}`;
  } catch (e) {
    $("records-count").textContent = e.message;
  }
}
$("load-records").addEventListener("click", loadRecords);

// ---------- quarantine ----------
async function loadQuarantine() {
  const { items } = await api("/v1/quarantine?limit=100");
  $("quarantine").replaceChildren(
    ...(items.length ? items.map((q) => el("div", { class: "q-item" },
      el("div", {}, el("strong", {}, q.connector_id), el("span", { class: "muted" }, `  #${q.id} · ${ago(q.created_at)}`)),
      el("div", { class: "error" }, (q.errors || []).join("; ")),
      el("pre", {}, JSON.stringify(q.raw_redacted, null, 1)))) : [el("p", { class: "muted" }, "Quarantine is empty.")]),
  );
}

// ---------- tabs + polling ----------
for (const b of document.querySelectorAll(".tab"))
  b.addEventListener("click", () => {
    for (const x of document.querySelectorAll(".tab")) x.classList.toggle("active", x === b);
    for (const t of ["connectors", "records", "quarantine"]) $(`tab-${t}`).classList.toggle("hidden", t !== b.dataset.tab);
    if (b.dataset.tab === "records") loadRecords();
    if (b.dataset.tab === "quarantine") loadQuarantine();
  });

refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 5000);
