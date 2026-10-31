-- Phase 3: circuit breaker pause window, per-run field hit stats (schema drift), resume marker.
alter table connectors add column paused_until timestamptz;
alter table runs add column field_stats jsonb;
alter table runs add column resumed boolean not null default false;
