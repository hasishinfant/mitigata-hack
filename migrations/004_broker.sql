-- Phase 6: only the broker registers configs, and it signs every version it approves.
alter table connector_versions add column broker_sig text;
-- The app role keeps reading configs and updating connector state (schedule, pause), but can no longer
-- create, change or delete config versions, connectors or tenants. A compromised worker/API cannot
-- point an existing secret at a new host.
revoke insert, update, delete on connector_versions from ix_app;
revoke insert, delete on connectors from ix_app;
revoke insert, update, delete on tenants from ix_app;
