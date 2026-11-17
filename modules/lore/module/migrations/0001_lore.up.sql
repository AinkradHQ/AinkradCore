-- Lore R1-01: the notes store. Every object starts with `lore_` (the Core refuses the migration
-- otherwise). A note's `text` is the Markdown document itself (T1). Saves, versions, links, tags and the
-- FTS table are created here and filled by R1-02 (save/merge/versions) and R1-04 (index/backlinks);
-- R1-01 writes only `lore_notes`. Nothing here holds a secret.

CREATE TABLE lore_notes (
    id          TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'ln_' AND length(id) = 15),
    kind        TEXT NOT NULL DEFAULT 'note' CHECK (kind IN ('note', 'daily')),
    day         TEXT UNIQUE CHECK (day IS NULL OR (kind = 'daily'
                    AND day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')),
    -- core_projects.id as text: no foreign key into a Core table; NULL = personal
    project     TEXT CHECK (project IS NULL OR kind = 'note'),
    title       TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    title_norm  TEXT NOT NULL,
    text        TEXT NOT NULL CHECK (length(text) <= 2000000),
    rev         INTEGER NOT NULL DEFAULT 1 CHECK (rev >= 1),
    import_run  TEXT,
    import_hash TEXT,
    created_by  TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    trashed_at  TEXT,
    CHECK ((kind = 'daily') = (day IS NOT NULL))
);
CREATE INDEX lore_notes_project ON lore_notes (project, updated_at);
CREATE INDEX lore_notes_trashed ON lore_notes (trashed_at) WHERE trashed_at IS NOT NULL;

-- The last saved texts per note, the base of a 3-way merge (T2).
CREATE TABLE lore_saves (
    note TEXT NOT NULL REFERENCES lore_notes (id) ON DELETE CASCADE,
    rev  INTEGER NOT NULL,
    text TEXT NOT NULL,
    at   TEXT NOT NULL,
    PRIMARY KEY (note, rev)
) WITHOUT ROWID;

CREATE TABLE lore_versions (
    id         TEXT PRIMARY KEY,
    note       TEXT NOT NULL REFERENCES lore_notes (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('auto', 'named', 'conflict')),
    name       TEXT,
    rev        INTEGER NOT NULL,
    text       TEXT NOT NULL,
    origin     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX lore_versions_note ON lore_versions (note, created_at);

-- `heading` is '' (not NULL) for a link without one, so the primary key really is unique.
CREATE TABLE lore_links (
    src               TEXT NOT NULL REFERENCES lore_notes (id) ON DELETE CASCADE,
    target_title_norm TEXT NOT NULL,
    heading           TEXT NOT NULL DEFAULT '',
    target            TEXT REFERENCES lore_notes (id) ON DELETE SET NULL,
    context           TEXT NOT NULL,
    PRIMARY KEY (src, target_title_norm, heading)
);
CREATE INDEX lore_links_target ON lore_links (target);

CREATE TABLE lore_tags (
    note TEXT NOT NULL REFERENCES lore_notes (id) ON DELETE CASCADE,
    tag  TEXT NOT NULL COLLATE NOCASE,
    PRIMARY KEY (note, tag)
);

-- Standalone (never `content=`): rowid = the note's rowid. Filled by R1-04.
CREATE VIRTUAL TABLE lore_fts USING fts5(title, body, tokenize = 'unicode61 remove_diacritics 2');

-- The one cross-module contract: what the Brain collector reads (T11).
CREATE VIEW lore_feed_v1 AS
    SELECT id, project, kind, title, text, rev, updated_at, trashed_at FROM lore_notes;
