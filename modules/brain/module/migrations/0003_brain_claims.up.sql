-- A session that works for a room (plan section 8, E6-1): the claim, with the chain it was checked
-- against. Module-only table; the session id is text, never a foreign key into the platform.
CREATE TABLE brain_session_rooms (
    session    TEXT PRIMARY KEY,
    room       TEXT NOT NULL REFERENCES brain_rooms(id),
    chain      TEXT NOT NULL,
    claimed_by TEXT NOT NULL,
    claimed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
-- A distillation of a room's new sources (E6-2). `state`: queued, needs_local_model, waiting
-- (no runner yet), running, done, failed. Ids and counts only; the text stays in the room's file.
CREATE TABLE brain_distils (
    id           TEXT PRIMARY KEY,
    room         TEXT NOT NULL REFERENCES brain_rooms(id),
    state        TEXT NOT NULL CHECK (state IN ('queued','needs_local_model','waiting','running','done','failed')),
    session      TEXT,
    requested_by TEXT NOT NULL,
    sources      INTEGER NOT NULL DEFAULT 0,
    candidates   INTEGER NOT NULL DEFAULT 0,
    detail       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
