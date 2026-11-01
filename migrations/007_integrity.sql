-- T7 + T8: staged ingestion, controlled promotion, Sync Integrity Receipts.
-- A sync (one or more runs of a connector stream, resumed from checkpoints) stages its records here. Nothing reaches
-- users / devices / events until the integrity evaluator verifies the whole sync; then one transaction on the run's
-- lock session promotes the staged rows. Held syncs wait for an operator (ix approve / ix discard).

create table stage_syncs (
  sync_id uuid primary key,
  connector_id text not null references connectors(id) on delete cascade,
  stream text not null,
  state text not null default 'open' check (state in ('open', 'held')),
  held_reason text,
  created_at timestamptz not null default now());
create index on stage_syncs (connector_id, stream);

create table stage_records (
  sync_id uuid not null references stage_syncs(sync_id) on delete cascade,
  entity text not null check (entity in ('user', 'device', 'event')),
  source_id text not null,
  fields jsonb not null,
  attributes jsonb not null default '{}',
  run_id uuid not null,
  fetched_at timestamptz not null,
  primary key (sync_id, entity, source_id));

-- One receipt per run (and per approve / discard). The body is canonical JSON; digest = sha256(canonical body).
-- The broker anchors each digest in the hash-chained audit ledger (anchored_seq). Evidence, not proof of upstream truth.
create table sync_receipts (
  id bigserial primary key,
  sync_id uuid not null,
  run_id uuid,
  connector_id text not null,
  stream text not null,
  kind text not null check (kind in ('run', 'approve', 'discard')),
  decision text not null,
  published boolean not null,
  body jsonb not null,
  digest text not null,
  anchored_seq bigint,
  created_at timestamptz not null default now());
create index on sync_receipts (connector_id, stream, id desc);
create index on sync_receipts (sync_id);

-- App role: stages and promotes (on its run's lock session), writes receipts, but can never change or delete one.
grant select, insert, update, delete on stage_syncs, stage_records to ix_app;
grant select, insert on sync_receipts to ix_app;
grant usage, select on sequence sync_receipts_id_seq to ix_app;
-- Broker: reads receipts to anchor their digest; sets anchored_seq only; deletes on connector removal.
grant select, delete on sync_receipts to ix_broker;
grant update (anchored_seq) on sync_receipts to ix_broker;
grant select, delete on stage_syncs, stage_records to ix_broker;
