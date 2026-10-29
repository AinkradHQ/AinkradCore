-- Artifacts (E15.12, pain #13): files, reports and screenshots agents publish, viewable without
-- opening an agent's conversation. Content is stored on disk by the server, content-addressed
-- (`<artifacts dir>/blobs/<sha256[0..2]>/<sha256>`, one file however often it is published);
-- each row is one publish, with where it came from. Size per file and storage per company are
-- settings (`artifact.max_file_bytes`, `artifact.company_quota_bytes`, decisions #47, #52); a
-- company's storage counts each distinct blob once.
CREATE TABLE artifacts (
    id             INTEGER PRIMARY KEY,
    company_id     INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    issue_id       INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    requirement_id INTEGER REFERENCES requirements(id) ON DELETE SET NULL,
    run_id         INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    agent_id       INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    name           TEXT    NOT NULL CHECK (name <> '' AND length(name) <= 200),
    kind           TEXT    NOT NULL CHECK (kind IN ('report', 'file', 'screenshot', 'other')),
    mime           TEXT    NOT NULL CHECK (mime <> ''),
    size           INTEGER NOT NULL CHECK (size >= 0),
    sha256         TEXT    NOT NULL CHECK (length(sha256) = 64),
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX artifacts_company ON artifacts (company_id, id);
CREATE INDEX artifacts_requirement ON artifacts (requirement_id);
CREATE INDEX artifacts_issue ON artifacts (issue_id);
CREATE INDEX artifacts_agent ON artifacts (agent_id);
CREATE INDEX artifacts_sha ON artifacts (company_id, sha256);

-- A publish by path: the file is in the run's worktree on its runner, which reads it (size
-- checked first, never outside the worktree) when its connection next looks (`sent`), and
-- answers with the content or why not (`done` / `failed`).
CREATE TABLE artifact_reads (
    id         INTEGER PRIMARY KEY,
    run_id     INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    path       TEXT    NOT NULL CHECK (path <> ''),
    max_bytes  INTEGER NOT NULL CHECK (max_bytes > 0),
    state      TEXT    NOT NULL DEFAULT 'pending'
               CHECK (state IN ('pending', 'sent', 'done', 'failed')),
    error      TEXT,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX artifact_reads_open ON artifact_reads (run_id) WHERE state IN ('pending', 'sent');
