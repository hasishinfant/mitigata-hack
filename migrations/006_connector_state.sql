-- Connector state belongs to the broker where it matters for security.
-- The app role (worker / API / scheduler) may still DISABLE connectors (kill switch, idle hygiene, operator),
-- pause and resume them (circuit breaker) and keep schedule bookkeeping. It may no longer:
--   - change which config version is active (rolling back to an older signed version with broader hosts);
--   - re-enable a disabled connector (undoing the kill switch). Re-enabling goes through the broker's
--     admin socket (ix enable / POST /v1/connectors/:id/enable), which records it in the audit ledger.

revoke update on connectors from ix_app;
grant update (status, disabled_reason, disabled_at, paused_until, next_run_at, last_success_at, enabled_at) on connectors to ix_app;

create function connectors_app_state_guard() returns trigger language plpgsql as $$
begin
  if current_user = 'ix_app' and old.status = 'disabled' and new.status is distinct from 'disabled' then
    raise exception 'connector % is disabled: only the broker can re-enable it (ix enable)', old.id
      using errcode = 'insufficient_privilege';
  end if;
  return new;
end $$;

create trigger connectors_app_state_guard before update on connectors
  for each row execute function connectors_app_state_guard();
