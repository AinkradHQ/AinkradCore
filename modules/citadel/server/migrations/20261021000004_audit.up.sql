-- Append-only audit log (brainstorm §7). Triggers reject every UPDATE and DELETE.
-- Entity, company and run ids are plain integers with no foreign key: an audit row must
-- outlive whatever it describes, so nothing may cascade into it or clear it.
-- AUTOINCREMENT keeps seq strictly increasing: a seq is never handed out twice.
CREATE TABLE audit_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor_kind  TEXT    NOT NULL CHECK (actor_kind IN ('user', 'agent', 'runner', 'system')),
    -- The user, agent or runner id; NULL for the system.
    actor_id    INTEGER,
    -- Dotted lowercase, e.g. `issue.state_changed`.
    action      TEXT    NOT NULL
                CHECK (action GLOB '[a-z]*.[a-z]*' AND action NOT GLOB '*[^a-z0-9_.]*'),
    -- What it happened to (`issue` + its id); both NULL when it names no single row.
    entity_kind TEXT    CHECK (entity_kind GLOB '[a-z]*' AND entity_kind NOT GLOB '*[^a-z_]*'),
    entity_id   INTEGER,
    company_id  INTEGER,
    run_id      INTEGER,
    details     TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(details)),
    CHECK ((actor_kind = 'system') = (actor_id IS NULL)),
    CHECK ((entity_kind IS NULL) = (entity_id IS NULL))
);
CREATE INDEX audit_events_entity ON audit_events (entity_kind, entity_id);
CREATE INDEX audit_events_company ON audit_events (company_id);
CREATE INDEX audit_events_run ON audit_events (run_id);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
