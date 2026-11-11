-- One import run's cleaned items before review (plan §4.3). Encrypted with the brain key.
CREATE TABLE items (
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
    proposal     TEXT,
    mark         TEXT CHECK (mark IN ('needed','refused')),
    warnings     TEXT NOT NULL DEFAULT '[]',
    pointer      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX items_proposal ON items(proposal, started_at);
CREATE TABLE proposals (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    kind_guess TEXT NOT NULL,
    kind       TEXT NOT NULL,
    signals    TEXT NOT NULL DEFAULT '[]',
    warnings   TEXT NOT NULL DEFAULT '[]',
    config     TEXT NOT NULL DEFAULT '{}',
    state      TEXT NOT NULL DEFAULT 'proposed' CHECK (state IN ('proposed','accepted','refused','merged','committed','held')),
    room       TEXT
);
-- Never any text: an item that was skipped, by reason code.
CREATE TABLE skips (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id TEXT NOT NULL,
    reason  TEXT NOT NULL
);
