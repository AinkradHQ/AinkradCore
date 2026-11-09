-- The client event stream (E10.2): one append-only, strictly increasing sequence over
-- everything the app shows live. Rows are references, written by triggers in the same
-- transaction as what they point at, so an event commits or rolls back with its change and
-- no write path can forget one. SQLite has one writer at a time, so seq order is commit
-- order: a reader never sees seq N+1 before seq N.
--   audit      -> audit_events.seq   (state changes, approvals, runs, every audited write)
--   transcript -> run_events.id      (run transcript chunks)
--   wake       -> wake_requests.id   (a wake queued)
-- Rows written before this migration have no events; the stream starts here.
CREATE TABLE events (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    kind   TEXT    NOT NULL CHECK (kind IN ('audit', 'transcript', 'wake')),
    ref_id INTEGER NOT NULL
);

CREATE TRIGGER events_from_audit AFTER INSERT ON audit_events
BEGIN
    INSERT INTO events (at, kind, ref_id) VALUES (NEW.at, 'audit', NEW.seq);
END;

CREATE TRIGGER events_from_transcript AFTER INSERT ON run_events
BEGIN
    INSERT INTO events (at, kind, ref_id) VALUES (NEW.at, 'transcript', NEW.id);
END;

CREATE TRIGGER events_from_wake AFTER INSERT ON wake_requests
BEGIN
    INSERT INTO events (at, kind, ref_id) VALUES (NEW.created_at, 'wake', NEW.id);
END;

CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;
