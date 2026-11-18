-- Lore R4-01: import runs (T12). A run stages items (not notes), is reviewed, then committed in chunks;
-- every step is persisted, so a run can be resumed after a restart and seen in the list. `import_origin` is
-- the identity of a source file (`mirror:<repo>:<path>` or `upload:<project>:<path>`): the same origin
-- imported again updates the note it made instead of making a second one. Nothing here is a secret.
ALTER TABLE lore_notes ADD COLUMN import_origin TEXT;
CREATE INDEX lore_notes_origin ON lore_notes (import_origin) WHERE import_origin IS NOT NULL;
CREATE INDEX lore_notes_import_hash ON lore_notes (import_hash) WHERE import_hash IS NOT NULL;

CREATE TABLE lore_imports (
    id           TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'li_' AND length(id) = 15),
    source       TEXT NOT NULL CHECK (source IN ('mirror', 'upload', 'apple_notes')),
    project      TEXT,
    repo         TEXT,
    state        TEXT NOT NULL CHECK (state IN ('staging', 'review', 'committing', 'committed',
                     'undoing', 'undone', 'abandoned')),
    -- entries refused outright (unsafe path, symlink, submodule, NUL, over a cap) and entries ignored (not Markdown, filtered
    -- folders): counted, never stored, so a hostile name is not kept.
    refused      INTEGER NOT NULL DEFAULT 0,
    ignored      INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    committed_at TEXT
);
CREATE INDEX lore_imports_state ON lore_imports (state, updated_at);

CREATE TABLE lore_import_items (
    run        TEXT NOT NULL REFERENCES lore_imports (id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    path       TEXT NOT NULL,
    origin     TEXT NOT NULL,
    title      TEXT NOT NULL,
    text       TEXT NOT NULL,
    hash       TEXT NOT NULL,
    tags       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags)),
    project    TEXT,
    match_note TEXT,
    flag       TEXT CHECK (flag IN ('duplicate', 'changed', 'conflict', 'too_large', 'skipped')),
    mark       TEXT NOT NULL DEFAULT 'include' CHECK (mark IN ('include', 'skip')),
    -- what commit did, once it has: the note touched, the version kept, and what undo needs to put back
    result     TEXT CHECK (result IS NULL OR result IN ('created', 'updated', 'conflict', 'unchanged', 'skipped')),
    note       TEXT,
    version    TEXT,
    rev_after  INTEGER,
    prev_hash  TEXT,
    prev_run   TEXT,
    undone     INTEGER NOT NULL DEFAULT 0 CHECK (undone IN (0, 1, 2)),
    PRIMARY KEY (run, seq),
    UNIQUE (run, origin)
) WITHOUT ROWID;
