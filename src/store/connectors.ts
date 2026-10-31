// Connector registry: configs are stored as versioned YAML text (with ${env.X} left un-interpolated)
// and re-validated against the current environment every time they're loaded.
import type pg from "pg";
import { resolveConnector, type ResolvedConnector } from "../config/load.ts";
import { validateConfigText, type Issue } from "../config/validate.ts";
import { withTx } from "./db.ts";

export class ConnectorConfigError extends Error {
  issues: Issue[];
  constructor(message: string, issues: Issue[]) {
    super(message);
    this.issues = issues;
  }
}

export type RegisterResult = { id: string; version: number; changed: boolean };

export async function registerConnector(
  pool: pg.Pool,
  yamlText: string,
  opts: {
    createdBy?: string;
    env?: Record<string, string | undefined>;
    mustExist?: boolean;
    mustNotExist?: boolean;
    /** Broker only: signs the approved version. Without it the broker will refuse to use the config. */
    sign?: (id: string, version: number, configHash: string) => string;
  } = {},
): Promise<RegisterResult> {
  const res = validateConfigText(yamlText, { env: opts.env });
  if (!res.ok || !res.config) throw new ConnectorConfigError("config is invalid", res.errors);
  const { id, tenant, source } = res.config.metadata;
  return withTx(pool, async (c) => {
    const existing = await c.query("select active_version from connectors where id = $1 for update", [id]);
    if (opts.mustNotExist && existing.rowCount)
      throw Object.assign(new Error(`connector ${id} already exists; use "ix update"`), { statusCode: 409 });
    if (opts.mustExist && !existing.rowCount) throw Object.assign(new Error(`connector ${id} does not exist; use "ix add"`), { statusCode: 404 });
    await c.query("insert into tenants (id, name) values ($1, $1) on conflict do nothing", [tenant]);
    if (existing.rowCount) {
      const cur = await c.query(
        "select v.config_hash from connector_versions v join connectors k on k.id = v.connector_id and k.active_version = v.version where k.id = $1",
        [id],
      );
      if (cur.rows[0]?.config_hash === res.configHash) {
        const version = existing.rows[0].active_version as number;
        // Same config: (re-)approve it if the broker is registering and the stored signature is missing or stale.
        if (opts.sign)
          await c.query("update connector_versions set broker_sig = $3 where connector_id = $1 and version = $2", [id, version, opts.sign(id, version, res.configHash)]);
        return { id, version, changed: false };
      }
    } else {
      await c.query("insert into connectors (id, tenant_id, source) values ($1, $2, $3)", [id, tenant, source]);
    }
    const next = await c.query("select coalesce(max(version), 0) + 1 as v from connector_versions where connector_id = $1", [id]);
    const version = Number(next.rows[0].v);
    await c.query(
      `insert into connector_versions (connector_id, version, config_yaml, config_hash, validated_at, created_by, broker_sig)
       values ($1, $2, $3, $4, now(), $5, $6)`,
      [id, version, yamlText, res.configHash, opts.createdBy ?? "cli", opts.sign ? opts.sign(id, version, res.configHash) : null],
    );
    await c.query("update connectors set active_version = $2, source = $3 where id = $1", [id, version, source]);
    return { id, version, changed: true };
  });
}

export async function loadActiveConnector(pool: pg.Pool, id: string, env = process.env): Promise<ResolvedConnector & { status: string }> {
  const r = await pool.query(
    `select k.status, v.config_yaml from connectors k
     join connector_versions v on v.connector_id = k.id and v.version = k.active_version where k.id = $1`,
    [id],
  );
  if (!r.rowCount) throw Object.assign(new Error(`connector ${id} not found (ix add <file>)`), { statusCode: 404 });
  const res = validateConfigText(r.rows[0].config_yaml as string, { env });
  if (!res.ok || !res.config) throw new ConnectorConfigError(`stored config for ${id} no longer validates`, res.errors);
  return { ...resolveConnector(res.config, res.configHash), status: r.rows[0].status as string };
}

export async function listConnectorIds(pool: pg.Pool): Promise<{ id: string; status: string }[]> {
  return (await pool.query("select id, status from connectors order by id")).rows;
}

/**
 * Broker-side load: only a version the broker signed, re-hashed from the stored YAML, on a connector
 * that isn't disabled. Anything else is refused, whatever the app database says.
 */
export async function loadSignedConnector(
  pool: pg.Pool,
  id: string,
  verify: (id: string, version: number, configHash: string, sig: string | null) => boolean,
  env = process.env,
): Promise<ResolvedConnector & { status: string; version: number }> {
  const r = await pool.query(
    `select k.status, k.active_version, v.config_yaml, v.config_hash, v.broker_sig from connectors k
     join connector_versions v on v.connector_id = k.id and v.version = k.active_version where k.id = $1`,
    [id],
  );
  if (!r.rowCount) throw new Error(`connector ${id} not found`);
  const row = r.rows[0];
  const res = validateConfigText(row.config_yaml as string, { env });
  if (res.configHash !== row.config_hash || !verify(id, row.active_version, res.configHash, row.broker_sig))
    throw new Error(`connector ${id} v${row.active_version} was not approved by the broker (re-register with ix update)`);
  if (!res.ok || !res.config) throw new ConnectorConfigError(`stored config for ${id} no longer validates`, res.errors);
  if (res.config.metadata.id !== id) throw new Error(`connector ${id}: stored config claims id ${res.config.metadata.id}`);
  return { ...resolveConnector(res.config, res.configHash), status: row.status as string, version: row.active_version as number };
}

export async function setConnectorEnabled(pool: pg.Pool, id: string, enabled: boolean, reason?: string): Promise<boolean> {
  const r = enabled
    ? await pool.query(
        "update connectors set status = 'enabled', disabled_reason = null, disabled_at = null, paused_until = null, enabled_at = now() where id = $1",
        [id],
      )
    : await pool.query("update connectors set status = 'disabled', disabled_reason = $2, disabled_at = now(), next_run_at = null where id = $1", [
        id, reason ?? "disabled by operator",
      ]);
  return (r.rowCount ?? 0) > 0;
}
