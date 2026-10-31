-- Phase 7: credential hygiene, alert delivery, incremental watermarks.
alter table alerts add column channel text;            -- slack | none | error
alter table alerts add column delivered_at timestamptz;
alter table connectors add column disabled_at timestamptz;
-- Which connector last learned scopes for a credential (broker writes granted_scopes / revocable_by_api).
alter table credentials add column scopes_seen_at timestamptz;

-- Credential metadata for posture cards. A view (owned by the migration role) exposes age, use and
-- scopes to ix_app without ciphertext, wrapped keys or nonces; ix_app still cannot read credentials.
create view credential_meta as
  select tenant_id, ref, created_at, last_used_at, expires_at, granted_scopes, scopes_seen_at, revocable_by_api
  from credentials;
grant select on credential_meta to ix_app, ix_broker;

-- Re-enabling a connector restarts its idle clock.
alter table connectors add column enabled_at timestamptz;
