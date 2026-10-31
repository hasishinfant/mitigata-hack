-- IntegrateX initial schema. Run as the admin/owner role (DATABASE_URL_ADMIN).
-- Role passwords are NOT set here; src/store/migrate.ts sets them from the env URLs.

create table tenants (id text primary key, name text not null, created_at timestamptz default now());

create table connectors (
  id text primary key, tenant_id text not null references tenants(id),
  source text not null, status text not null default 'enabled',
  active_version int, last_success_at timestamptz, disabled_reason text);

create table connector_versions (
  connector_id text references connectors(id) on delete cascade, version int,
  config_yaml text not null, config_hash text not null, validated_at timestamptz, created_by text,
  primary key (connector_id, version));

create table credentials (
  ref text, tenant_id text references tenants(id),
  ciphertext bytea not null, wrapped_dek bytea not null, nonce bytea not null,
  created_at timestamptz default now(), last_used_at timestamptz, expires_at timestamptz,
  granted_scopes text[], revocable_by_api boolean, primary key (tenant_id, ref));

create table runs (
  id uuid primary key, connector_id text references connectors(id) on delete cascade, stream text,
  status text not null, started_at timestamptz, finished_at timestamptz,
  requests int default 0, records_ok int default 0, records_quarantined int default 0,
  retries int default 0, rate_limited_ms int default 0, last_error text, config_hash text);
create index on runs (connector_id, started_at desc);

create table checkpoints (
  connector_id text references connectors(id) on delete cascade, stream text,
  cursor_value text, page_state jsonb, updated_at timestamptz,
  primary key (connector_id, stream));

create table quarantine (
  id bigserial primary key, run_id uuid references runs(id) on delete cascade, connector_id text,
  raw_redacted jsonb, errors jsonb not null, created_at timestamptz default now());
create index on quarantine (connector_id, created_at desc);

create table users (
  tenant_id text, source text, source_id text,
  name text, email text, status text, last_login timestamptz,
  attributes jsonb default '{}', connector_id text, run_id uuid, fetched_at timestamptz not null,
  primary key (tenant_id, source, source_id));
create index on users (tenant_id, lower(email));

create table devices (
  tenant_id text, source text, source_id text,
  hostname text, ip inet, os text, owner text, last_seen timestamptz,
  attributes jsonb default '{}', connector_id text, run_id uuid, fetched_at timestamptz not null,
  primary key (tenant_id, source, source_id));

create table events (
  tenant_id text, source text, source_id text,
  type text not null, severity text check (severity in ('info','low','medium','high','critical')),
  ts timestamptz, description text,
  attributes jsonb default '{}', connector_id text, run_id uuid, fetched_at timestamptz not null,
  primary key (tenant_id, source, source_id));
create index on events (tenant_id, type, ts desc);

create table audit_ledger (
  seq bigserial primary key, ts timestamptz default now(), actor text, connector_id text,
  action text, method text, host text, path text, status int, records int, decision text,
  prev_hash text not null, hash text not null);

create table alerts (
  id bigserial primary key, connector_id text, kind text, message text,
  created_at timestamptz default now(), delivered boolean default false);

-- Append-only ledger, enforced even against the table owner (grants alone don't bind the owner).
create function audit_ledger_append_only() returns trigger language plpgsql as $$
begin
  raise exception 'audit_ledger is append-only (% blocked)', tg_op;
end $$;
create trigger audit_ledger_no_update before update or delete on audit_ledger
  for each row execute function audit_ledger_append_only();
create trigger audit_ledger_no_truncate before truncate on audit_ledger
  for each statement execute function audit_ledger_append_only();

-- Roles. LOGIN without password here; migrate.ts sets passwords from env.
do $$ begin
  if not exists (select from pg_roles where rolname = 'ix_app') then create role ix_app login; end if;
  if not exists (select from pg_roles where rolname = 'ix_broker') then create role ix_broker login; end if;
end $$;

revoke all on all tables in schema public from public;
grant usage on schema public to ix_app, ix_broker;

-- ix_broker: everything, including credentials. Ledger: read (for prev_hash) + insert only.
grant select, insert, update, delete on all tables in schema public to ix_broker;
revoke update, delete, truncate on audit_ledger from ix_broker;

-- ix_app: everything except credentials. Ledger: read only.
grant select, insert, update, delete on all tables in schema public to ix_app;
revoke all on credentials from ix_app;
revoke insert, update, delete, truncate on audit_ledger from ix_app;

grant usage, select on all sequences in schema public to ix_app, ix_broker;
revoke all on sequence audit_ledger_seq_seq from ix_app;
