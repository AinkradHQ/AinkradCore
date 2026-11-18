-- Leyline Y4-02: pre-set commands. 1 to 20 steps (each a command line run by the remote user's
-- shell), an optional scope that says which hosts it is for, and the two flags the gate and the run
-- read: `read_only` (an AI may run it on a read-only host) and `confirm` (a run must say it was
-- confirmed). A run snapshots the steps when the gate decides; editing a row never changes one in flight.
CREATE TABLE leyline_commands (
    id          TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'lc_'),
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(name) BETWEEN 1 AND 64 AND name = trim(name)),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    steps       TEXT NOT NULL CHECK (json_valid(steps) AND json_array_length(steps) BETWEEN 1 AND 20),
    scope_kind  TEXT NOT NULL DEFAULT 'any' CHECK (scope_kind IN ('any', 'host', 'group', 'tag', 'project')),
    scope_value TEXT,
    scope_role  TEXT CHECK (scope_role IS NULL OR scope_role IN ('production', 'staging', 'development', 'other')),
    read_only   INTEGER NOT NULL DEFAULT 0 CHECK (read_only IN (0, 1)),
    confirm     INTEGER NOT NULL DEFAULT 0 CHECK (confirm IN (0, 1)),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((scope_kind = 'any' AND scope_value IS NULL AND scope_role IS NULL)
        OR (scope_kind IN ('host', 'group', 'tag') AND scope_value IS NOT NULL AND scope_role IS NULL)
        OR (scope_kind = 'project' AND scope_value IS NOT NULL))
);
