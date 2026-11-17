-- Design V1-01: the document store. Every object starts with `design_` (the Core refuses the migration
-- otherwise). The CRDT bytes (`snapshot`, `design_updates.data`, `design_versions.state`) are written by
-- the sync actor (V1-03); this story only creates their homes and the docs CRUD. Approvals, comments,
-- compares (review stories) and the asset library (V4-01) get their own later migrations.
-- Nothing here holds a secret.

CREATE TABLE design_docs (
    id            TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'dd_'),
    kind          TEXT NOT NULL CHECK (kind IN ('design', 'system', 'mockup')),
    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100 AND name = trim(name)),
    state         TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'archived')),
    -- the design system a `design` uses; only a design names one
    system        TEXT REFERENCES design_docs (id) CHECK (system IS NULL OR kind = 'design'),
    snapshot      BLOB,
    snapshot_seq  INTEGER NOT NULL DEFAULT 0,
    manifest      TEXT CHECK (manifest IS NULL OR json_valid(manifest)),
    ai_paused     INTEGER NOT NULL DEFAULT 0 CHECK (ai_paused IN (0, 1)),
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE design_updates (
    doc    TEXT NOT NULL REFERENCES design_docs (id) ON DELETE CASCADE,
    seq    INTEGER NOT NULL,
    data   BLOB NOT NULL,
    origin TEXT NOT NULL,
    at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (doc, seq)
) WITHOUT ROWID;

CREATE TABLE design_versions (
    id         TEXT PRIMARY KEY,
    doc        TEXT NOT NULL REFERENCES design_docs (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('auto', 'named', 'approval')),
    name       TEXT,
    state      BLOB NOT NULL,
    origin     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX design_versions_doc ON design_versions (doc, created_at);

-- The review unit: a top-level frame (or a mockup manifest screen).
CREATE TABLE design_screens (
    doc       TEXT NOT NULL REFERENCES design_docs (id) ON DELETE CASCADE,
    screen    TEXT NOT NULL,
    direction TEXT,
    states    TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(states)),
    PRIMARY KEY (doc, screen)
);

-- Related, not owned (D2): project = core_projects.id as text, no foreign key into a Core table
-- (the API checks it through the Projects store). Collections and assets arrive with V4-01.
CREATE TABLE design_links (
    item_kind TEXT NOT NULL CHECK (item_kind IN ('doc', 'collection', 'asset')),
    item      TEXT NOT NULL,
    project   TEXT NOT NULL CHECK (project <> '' AND project NOT GLOB '*[^0-9]*'),
    PRIMARY KEY (item_kind, item, project)
);
CREATE INDEX design_links_project ON design_links (project);

CREATE TABLE design_session_docs (
    session TEXT NOT NULL,
    doc     TEXT NOT NULL REFERENCES design_docs (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('directions', 'edit', 'review', 'build')),
    PRIMARY KEY (session, doc)
);
