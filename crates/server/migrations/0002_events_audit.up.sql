-- The event bus and audit hardening (E1-04, E1-10). Additive to the baseline: two registries, the
-- events' retention floor, and the audit hash chain. Tables here without `user_id` are
-- allow-listed in `user_owned_tables_carry_user_id`: event_kinds and audit_actions (a name
-- belongs to the platform or a module, not to a user) and events_floor (one row, the log's).

-- Registered event kinds and audit actions (E1-04.2, E1-10.2). `connect` registers the
-- platform's (`store::kinds`), `migrate_modules` each module's. A name is dotted lowercase; a
-- module's starts with its id and a dot. Inserting an event or an audit row whose kind or action
-- is not registered is refused here, so the explicit append, the audit trigger and any raw
-- INSERT are held to the same list.
CREATE TABLE event_kinds (
    kind  TEXT NOT NULL PRIMARY KEY
          CHECK (kind GLOB '[a-z]*' AND kind NOT GLOB '*[^a-z0-9_.]*'
                 AND kind NOT GLOB '*..*' AND kind NOT GLOB '*.'),
    owner TEXT NOT NULL CHECK (owner = 'core' OR kind GLOB owner || '.?*')
) WITHOUT ROWID;

CREATE TABLE audit_actions (
    action TEXT NOT NULL PRIMARY KEY
           CHECK (action GLOB '[a-z]*.[a-z]*' AND action NOT GLOB '*[^a-z0-9_.]*'
                  AND action NOT GLOB '*..*' AND action NOT GLOB '*.'),
    owner  TEXT NOT NULL CHECK (owner = 'core' OR action GLOB owner || '.?*')
) WITHOUT ROWID;

CREATE TRIGGER events_kind_registered BEFORE INSERT ON events
WHEN NOT EXISTS (SELECT 1 FROM event_kinds WHERE kind = NEW.kind)
BEGIN
    SELECT RAISE(ABORT, 'unknown event kind');
END;

CREATE TRIGGER audit_events_action_registered BEFORE INSERT ON audit_events
WHEN NOT EXISTS (SELECT 1 FROM audit_actions WHERE action = NEW.action)
BEGIN
    SELECT RAISE(ABORT, 'unknown audit action');
END;

-- Retention (E1-04.4). Events at or below the floor are gone; a client resuming below it gets a
-- 410 and re-syncs. The floor only rises, and only rows at or below it may be deleted: the
-- append-only rule still holds for every event a client may still ask for, and trimming is two
-- statements in one transaction (raise the floor, delete below it), done by
-- `store::events::trim`. Audit rows are never trimmed.
CREATE TABLE events_floor (
    id  INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL CHECK (seq >= 0)
);

INSERT INTO events_floor (id, seq) VALUES (1, 0);

CREATE TRIGGER events_floor_only_rises BEFORE UPDATE ON events_floor
WHEN NEW.seq < OLD.seq OR NEW.id IS NOT OLD.id
BEGIN
    SELECT RAISE(ABORT, 'the events floor only rises');
END;

CREATE TRIGGER events_floor_no_delete BEFORE DELETE ON events_floor
BEGIN
    SELECT RAISE(ABORT, 'the events floor only rises');
END;

DROP TRIGGER events_no_delete;

CREATE TRIGGER events_no_delete BEFORE DELETE ON events
WHEN OLD.seq > (SELECT seq FROM events_floor)
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

-- The audit hash chain (E1-10.1). `hash` is the SHA-256 of the row's canonical form, which
-- includes the previous row's hash (`store::audit::chain`). SQLite cannot hash, so
-- `store::audit::append` computes it; this trigger makes that the only way in: a row must name
-- the newest row's hash (32 zero bytes when there is none, or it predates the chain) and take
-- the next seq. Rows from before this migration keep a NULL hash; `audit verify` counts them.
ALTER TABLE audit_events ADD COLUMN prev_hash BLOB;
ALTER TABLE audit_events ADD COLUMN hash BLOB;

CREATE TRIGGER audit_events_chained BEFORE INSERT ON audit_events
WHEN typeof(NEW.hash) IS NOT 'blob' OR length(NEW.hash) <> 32
  OR NEW.prev_hash IS NOT coalesce(
      (SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1), zeroblob(32))
  OR NEW.seq IS NOT coalesce(
      (SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'), 0) + 1
BEGIN
    SELECT RAISE(ABORT, 'audit rows are hash-chained; append through store::audit::append');
END;
