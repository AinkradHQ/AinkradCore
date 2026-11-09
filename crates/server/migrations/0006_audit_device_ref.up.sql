-- Devices are named by their opaque `d_…` id on the event stream (handshake spec §3, §15.4;
-- KAN-252): an audit row about a device keeps its row number in `entity_id` (the hash chain
-- covers it), but the `audit` event it produces carries `entity_id` NULL and the `d_…` id as
-- `entity_ref`. Other kinds carry their id in both, `entity_ref` as text.
DROP TRIGGER events_from_audit;

CREATE TRIGGER events_from_audit AFTER INSERT ON audit_events
BEGIN
    INSERT INTO events (at, kind, payload) VALUES (NEW.at, 'audit', json_object(
        'audit_seq', NEW.seq,
        'action', NEW.action,
        'actor_kind', NEW.actor_kind,
        'actor_id', NEW.actor_id,
        'entity_kind', NEW.entity_kind,
        'entity_id', CASE WHEN NEW.entity_kind = 'device' THEN NULL ELSE NEW.entity_id END,
        'entity_ref', CASE WHEN NEW.entity_kind = 'device'
            THEN (SELECT id FROM core_devices WHERE seq = NEW.entity_id)
            ELSE CAST(NEW.entity_id AS TEXT) END,
        'details', json(NEW.details)));
END;
