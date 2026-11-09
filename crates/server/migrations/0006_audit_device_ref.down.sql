DROP TRIGGER events_from_audit;

CREATE TRIGGER events_from_audit AFTER INSERT ON audit_events
BEGIN
    INSERT INTO events (at, kind, payload) VALUES (NEW.at, 'audit', json_object(
        'audit_seq', NEW.seq,
        'action', NEW.action,
        'actor_kind', NEW.actor_kind,
        'actor_id', NEW.actor_id,
        'entity_kind', NEW.entity_kind,
        'entity_id', NEW.entity_id,
        'details', json(NEW.details)));
END;
