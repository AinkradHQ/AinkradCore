-- A room's file (plan §4.4). Phase 1 writes `sources`, `op_log` and `outbox`; `records` waits for
-- distillation and `room_audit` for the first record change.
CREATE TABLE sources (
    item_id      TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL UNIQUE,
    source_kind  TEXT NOT NULL,
    device       TEXT NOT NULL,
    path         TEXT NOT NULL,
    project_hint TEXT,
    author_kind  TEXT NOT NULL,
    author_name  TEXT NOT NULL,
    title        TEXT NOT NULL,
    text         TEXT NOT NULL,
    links        TEXT NOT NULL DEFAULT '[]',
    started_at   TEXT NOT NULL,
    ended_at     TEXT,
    run          TEXT NOT NULL,
    assigned_by  TEXT NOT NULL CHECK (assigned_by IN ('user','rule')),
    needed       INTEGER NOT NULL DEFAULT 0,
    pointer      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE records (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL CHECK (type IN ('decision','fact','preference','rule','project-state','task','summary')),
    status     TEXT NOT NULL DEFAULT 'candidate',
    body       TEXT NOT NULL,
    tags       TEXT NOT NULL DEFAULT '[]',
    source_ids TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE TABLE op_log (
    seq  INTEGER PRIMARY KEY AUTOINCREMENT,
    op   TEXT NOT NULL,
    ref  TEXT NOT NULL,
    at   TEXT NOT NULL
);
CREATE TABLE room_audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    action  TEXT NOT NULL,
    detail  TEXT NOT NULL DEFAULT '{}',
    at      TEXT NOT NULL
);
CREATE TABLE outbox (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    op_seq INTEGER NOT NULL,
    sent   INTEGER NOT NULL DEFAULT 0
);
