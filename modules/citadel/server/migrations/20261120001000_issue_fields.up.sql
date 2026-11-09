-- Issue fields for the prototype (API minor 18): a five-level priority (the bool `priority`
-- stays, true from `high` up, and still orders wakes), acceptance criteria as a JSON array of
-- `{text, done}`, and the kinds `chore` and `spike`.
ALTER TABLE issues ADD COLUMN priority_level TEXT NOT NULL DEFAULT 'none'
    CHECK (priority_level IN ('none', 'low', 'medium', 'high', 'urgent'));
UPDATE issues SET priority_level = 'high' WHERE priority = 1;
ALTER TABLE issues ADD COLUMN criteria TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(criteria));

-- SQLite cannot alter a CHECK, and rebuilding `issues` would cascade through every table that
-- references it, so the kind list is edited in place: the procedure SQLite documents for
-- relaxing a CHECK. RESET reloads this connection's schema, which the edit alone leaves stale; the
-- throwaway table bumps the schema cookie, so every other connection reparses.
PRAGMA writable_schema = ON;
UPDATE sqlite_schema SET sql = replace(sql, 'kind IN (''story'', ''task'', ''bug'', ''subtask'')',
    'kind IN (''story'', ''task'', ''bug'', ''chore'', ''spike'', ''subtask'')')
WHERE type = 'table' AND name = 'issues';
PRAGMA writable_schema = RESET;
CREATE TABLE issue_kind_schema_bump (x);
DROP TABLE issue_kind_schema_bump;
