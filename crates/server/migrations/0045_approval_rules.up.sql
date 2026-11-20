-- "Always for this project" (Core 0.10, E14): an allow rule a person made when approving one tool
-- call. `tool` is the harness's tool name; `pattern` is a normalised matcher derived from the call
-- (a shell command's first words, or a path prefix inside the project folder). A rule only covers
-- a call that the positive allowlist (`agents::rules`) accepts again at use, so a stored row never
-- widens what the allowlist allows.
CREATE TABLE core_approval_rules (
    id         INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES core_projects(id) ON DELETE CASCADE,
    tool       TEXT    NOT NULL,
    pattern    TEXT    NOT NULL,
    created_by TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    UNIQUE (project_id, tool, pattern)
);
CREATE INDEX core_approval_rules_by_project ON core_approval_rules (project_id);
