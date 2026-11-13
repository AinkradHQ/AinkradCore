ALTER TABLE core_agent_sessions DROP COLUMN origin_root_ref;
ALTER TABLE core_agent_sessions DROP COLUMN origin_root;
ALTER TABLE core_agent_sessions DROP COLUMN origin_ref;
ALTER TABLE core_agent_sessions DROP COLUMN origin;
DROP INDEX audit_events_origin;
ALTER TABLE audit_events DROP COLUMN origin_root_ref;
ALTER TABLE audit_events DROP COLUMN origin_root;
ALTER TABLE audit_events DROP COLUMN origin_ref;
ALTER TABLE audit_events DROP COLUMN origin;
