-- Design V1-04: comments and approvals. Versions already live in `design_versions` (0001); this adds the
-- guard that makes an approval's frozen state truly frozen. Nothing here holds a secret.

-- A comment is pinned to a screen (a top-level frame id), optionally to a node or a point, and may reply to
-- another comment of the same doc. Resolving keeps the row.
CREATE TABLE design_comments (
    id          TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'dc_'),
    doc         TEXT NOT NULL REFERENCES design_docs (id) ON DELETE CASCADE,
    screen      TEXT NOT NULL,
    node        TEXT,
    x           REAL,
    y           REAL,
    version     TEXT REFERENCES design_versions (id),
    parent      TEXT REFERENCES design_comments (id),
    body        TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 4000),
    author      TEXT NOT NULL,
    resolved_at TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX design_comments_doc ON design_comments (doc, screen, created_at);

-- One row per screen: which frozen version is approved. `baseline` and `fidelity` are filled by the review
-- stories (V6-02); `changed` is set by them too when the screen moves on from the approved version.
CREATE TABLE design_approvals (
    doc        TEXT NOT NULL REFERENCES design_docs (id) ON DELETE CASCADE,
    screen     TEXT NOT NULL,
    version    TEXT NOT NULL REFERENCES design_versions (id),
    state      TEXT NOT NULL CHECK (state IN ('approved', 'changed', 'withdrawn')),
    baseline   TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(baseline)),
    fidelity   TEXT CHECK (fidelity IS NULL OR json_valid(fidelity)),
    decided_by TEXT NOT NULL,
    decided_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (doc, screen)
);

-- An approval version never changes and is never removed (the compaction only prunes `auto` ones).
CREATE TRIGGER design_versions_frozen_update BEFORE UPDATE ON design_versions
WHEN OLD.kind = 'approval'
BEGIN SELECT RAISE(ABORT, 'an approval version is frozen'); END;
CREATE TRIGGER design_versions_frozen_delete BEFORE DELETE ON design_versions
WHEN OLD.kind = 'approval'
BEGIN SELECT RAISE(ABORT, 'an approval version is frozen'); END;
