DROP TRIGGER audit_events_chained;
ALTER TABLE audit_events DROP COLUMN hash;
ALTER TABLE audit_events DROP COLUMN prev_hash;
DROP TRIGGER events_no_delete;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;
DROP TABLE events_floor;
DROP TRIGGER audit_events_action_registered;
DROP TRIGGER events_kind_registered;
DROP TABLE audit_actions;
DROP TABLE event_kinds;
