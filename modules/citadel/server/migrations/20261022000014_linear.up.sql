-- Linear sync (E9.4, #26). A project synced with a Linear team: its API, the token file (the
-- path only) and the cursor (the latest `updatedAt` read). Each synced issue is linked to its
-- Linear issue, with what both sides held at the last sync, field by field: a side whose value
-- differs from it changed since, which is how neither side's own writes echo back.
--
-- issues.updated_at is when an issue's synced fields last changed in Citadel; it settles a
-- field both sides changed (the later write wins).

CREATE TABLE project_linear (
    project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    team_id    TEXT    NOT NULL,
    api_url    TEXT    NOT NULL,
    token_file TEXT    NOT NULL,
    cursor     TEXT
);

CREATE TABLE linear_issues (
    issue_id   INTEGER PRIMARY KEY REFERENCES issues(id) ON DELETE CASCADE,
    linear_id  TEXT    NOT NULL UNIQUE,
    identifier TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    -- The Linear state type: backlog, unstarted, started, completed or canceled.
    state      TEXT    NOT NULL,
    -- A name both sides know (an agent's, a Linear member's), or NULL.
    assignee   TEXT,
    synced_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

ALTER TABLE issues ADD COLUMN updated_at TEXT;
CREATE TRIGGER issues_updated_at AFTER UPDATE OF title, body, state, next_agent_id, next_user_id
ON issues
BEGIN
    UPDATE issues SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;
