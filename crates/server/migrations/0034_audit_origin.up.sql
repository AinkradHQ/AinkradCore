-- Origin on every audit row (E1-2): what started the action, and the root of the chain it
-- belongs to. All four are NULL on rows from before this migration (read as "unknown") and are
-- part of the hash only when set, so old rows still verify. `origin_ref` names the device,
-- job or session; the root's kind and ref name the first link.
ALTER TABLE audit_events ADD COLUMN origin TEXT
    CHECK (origin IN ('person', 'schedule', 'brain_import', 'brain_distil', 'ai_session', 'handoff', 'system'));
ALTER TABLE audit_events ADD COLUMN origin_ref TEXT;
ALTER TABLE audit_events ADD COLUMN origin_root TEXT
    CHECK (origin_root IN ('person', 'schedule', 'brain_import', 'brain_distil', 'ai_session', 'handoff', 'system'));
ALTER TABLE audit_events ADD COLUMN origin_root_ref TEXT;
CREATE INDEX audit_events_origin ON audit_events (origin) WHERE origin IS NOT NULL;

-- A session keeps the origin it was started with (E1-3), set by the Core at creation.
ALTER TABLE core_agent_sessions ADD COLUMN origin TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN origin_ref TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN origin_root TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN origin_root_ref TEXT;
