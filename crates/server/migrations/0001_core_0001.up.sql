-- The platform baseline (E1-03.1): the Core's own tables, squashed from Citadel's platform
-- migrations instead of replaying its 150. No foreign key or trigger reaches a module's table.

-- Convention (#18): every user-owned row carries
--   user_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id)
-- so roles and more users can come later without a data migration.
-- Today there is a single admin user (id 1).
CREATE TABLE users (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO users (id, name) VALUES (1, 'admin');

-- A per-device API key (E10.3): only its SHA-256 is kept. A revoked key keeps its row. The
-- push token (hex, from the app) and whether it is a development build's (the sandbox
-- gateway) are where its pushes go (E10.4).
CREATE TABLE device_keys (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name         TEXT    NOT NULL,
    key_hash     BLOB    NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT,
    revoked_at   TEXT,
    push_token   TEXT
                 CHECK (push_token IS NULL OR (length(push_token) BETWEEN 32 AND 200
                                               AND push_token NOT GLOB '*[^0-9a-f]*')),
    push_sandbox INTEGER NOT NULL DEFAULT 0 CHECK (push_sandbox IN (0, 1))
);

-- Device pairing: the admin asks for a 6-character code, the new device trades it, once and
-- before it expires, for its own device key. Only the code's hash is kept.
CREATE TABLE device_pairings (
    code_hash     BLOB    PRIMARY KEY,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,
    used_at       TEXT,
    device_key_id INTEGER REFERENCES device_keys(id) ON DELETE SET NULL
) WITHOUT ROWID;

-- Append-only audit log (brainstorm §7). Triggers reject every UPDATE and DELETE.
-- The entity id is a plain integer with no foreign key: an audit row must outlive whatever it
-- describes, so nothing may cascade into it or clear it.
-- AUTOINCREMENT keeps seq strictly increasing: a seq is never handed out twice.
CREATE TABLE audit_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- `user` or `system` from the platform; a module may bring its own kinds of actor.
    actor_kind  TEXT    NOT NULL
                CHECK (actor_kind GLOB '[a-z]*' AND actor_kind NOT GLOB '*[^a-z_]*'),
    -- The actor's id; NULL for the system.
    actor_id    INTEGER,
    -- Dotted lowercase, e.g. `device_key.revoked`.
    action      TEXT    NOT NULL
                CHECK (action GLOB '[a-z]*.[a-z]*' AND action NOT GLOB '*[^a-z0-9_.]*'),
    -- What it happened to (`device_key` + its id); both NULL when it names no single row.
    entity_kind TEXT    CHECK (entity_kind GLOB '[a-z]*' AND entity_kind NOT GLOB '*[^a-z_]*'),
    entity_id   INTEGER,
    details     TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(details)),
    CHECK ((actor_kind = 'system') = (actor_id IS NULL)),
    CHECK ((entity_kind IS NULL) = (entity_id IS NULL))
);
CREATE INDEX audit_events_entity ON audit_events (entity_kind, entity_id);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

-- The client event stream (E10.2): one append-only, strictly increasing sequence over
-- everything the app shows live. Each row carries its own `kind` and JSON `payload`, so a
-- module adds kinds without a schema change (a registry of kinds comes with E1-04.2). Rows
-- are written in the same transaction as the change they describe; the platform's own,
-- `audit`, by a trigger, so no write path can forget one. SQLite has one writer at a time,
-- so seq order is commit order: a reader never sees seq N+1 before seq N.
CREATE TABLE events (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    kind    TEXT    NOT NULL CHECK (kind <> ''),
    payload TEXT    NOT NULL CHECK (json_valid(payload))
);

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

CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

-- How far the pusher has read the events (E10.4); no row before its first pass.
CREATE TABLE push_cursor (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    after INTEGER NOT NULL
);

-- Configurable limits (E15.17, decision #52): a value per (key, scope); the registry in
-- `ainkrad_core::settings` holds each key's default, bounds and allowed scopes, and the most
-- specific scope wins. `scope_id` is 0 for the server, the platform's only scope so far. Every
-- set and reset is audited (`setting.set` / `setting.reset`), which is the change history.
CREATE TABLE settings (
    key             TEXT    NOT NULL CHECK (key <> ''),
    scope_kind      TEXT    NOT NULL CHECK (scope_kind IN ('server')),
    scope_id        INTEGER NOT NULL CHECK ((scope_kind = 'server') = (scope_id = 0)),
    value           TEXT    NOT NULL CHECK (json_valid(value)),
    updated_by_kind TEXT    NOT NULL
                    CHECK (updated_by_kind GLOB '[a-z]*' AND updated_by_kind NOT GLOB '*[^a-z_]*'),
    updated_by_id   INTEGER,
    updated_at      TEXT    NOT NULL,
    PRIMARY KEY (key, scope_kind, scope_id)
);
