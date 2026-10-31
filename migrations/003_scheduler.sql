-- Phase 5: job queue schema (pg-boss) owned by the app role, schedule bookkeeping, run trigger.
create schema if not exists pgboss authorization ix_app;
alter table connectors add column next_run_at timestamptz;
alter table runs add column trigger text not null default 'manual';
