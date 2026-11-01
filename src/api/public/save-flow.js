// Builder "Save": register the connector, then store its secrets. No DOM access, so it can be tested against the
// real API (test/phase6.test.ts). Loaded as a plain script before builder.js; exposes globalThis.ixSaveConnector.
//
// Order: register first, then secrets. A secret already in the broker but used by no approved connector (or a new
// host for a secret in use) needs an explicit approval of the hosts it will be sent to; registering first means a
// brand-new secret needs none.
//
// Intermediate state: if registration succeeds but a secret fails to store, the connector is registered without
// that credential. The flow says so plainly and keeps the unsent values. Saving again is safe: the config text is
// unchanged, so the broker reports "unchanged" (no new version) and only the missing secrets are sent.
"use strict";

/**
 * @param {{
 *   api: (path: string, opts: object) => Promise<any>,
 *   headers: (extra?: object) => object,
 *   confirm: (question: string) => boolean,
 *   log: (line: string, cls?: string) => void,
 *   yaml: string, id: string, tenant: string,
 *   secrets: { ref: string, value: string }[],
 * }} o
 * @returns {Promise<{ state: "declined" } | { state: "ok" | "registered_without_secrets", reg: any, stored: string[], failed: { ref: string, error: string }[] }>}
 */
async function ixSaveConnector(o) {
  const register = async (confirmHosts) => {
    const q = confirmHosts ? "?confirm_hosts=1" : "";
    try {
      return await o.api(`/v1/connectors${q}`, { method: "POST", headers: o.headers({ "content-type": "text/yaml" }), body: o.yaml });
    } catch (e) {
      if (!/already exists/.test(e.message)) throw e;
      return o.api(`/v1/connectors/${encodeURIComponent(o.id)}${q}`, { method: "PUT", headers: o.headers({ "content-type": "text/yaml" }), body: o.yaml });
    }
  };

  let reg;
  try {
    reg = await register(false);
  } catch (e) {
    if (!/--confirm-hosts/.test(e.message)) throw e;
    const why = e.message.replace(/ If that is intended.*$/, "");
    o.log(`⚠ ${why}`, "bad");
    if (!o.confirm(`${why}\n\nAllow the broker to send these secrets to these hosts?`)) {
      o.log("✖ not registered: host approval declined", "bad");
      return { state: "declined" };
    }
    reg = await register(true);
    o.log(`✔ host approval recorded in the audit ledger${reg.newHosts ? `: ${reg.newHosts.join(", ")}` : ""}`, "ok");
  }
  o.log(`✔ ${reg.id} v${reg.version} ${reg.changed ? "registered and signed by the broker" : "unchanged (no new version)"}`, "ok");

  const stored = [];
  const failed = [];
  for (const s of o.secrets) {
    if (!s.value) {
      o.log(`secret "${s.ref}": no value entered, using the stored one if it exists`);
      continue;
    }
    try {
      const r = await o.api(`/v1/secrets/${encodeURIComponent(s.ref)}?tenant=${encodeURIComponent(o.tenant)}`, {
        method: "PUT", headers: o.headers({ "content-type": "application/json" }), body: JSON.stringify({ value: s.value }),
      });
      stored.push(s.ref);
      o.log(`✔ secret "${r.ref}" stored encrypted in the broker (${r.chars} chars)`, "ok");
    } catch (e) {
      failed.push({ ref: s.ref, error: e.message });
      o.log(`✖ secret "${s.ref}" was NOT stored: ${e.message}`, "bad");
    }
  }
  if (failed.length) {
    o.log(
      `⚠ ${reg.id} v${reg.version} is registered, but ${failed.map((f) => `"${f.ref}"`).join(", ")} ${failed.length === 1 ? "is" : "are"} not stored. ` +
        "Runs will fail (auth_failed) until it is. Fix the problem and press Save again: the config is unchanged, " +
        "so no new version is created and only the missing secrets are sent. Entered values were kept.",
      "bad",
    );
    return { state: "registered_without_secrets", reg, stored, failed };
  }
  return { state: "ok", reg, stored, failed };
}

globalThis.ixSaveConnector = ixSaveConnector;
