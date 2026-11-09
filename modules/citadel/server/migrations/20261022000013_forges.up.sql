-- Git hosts (E9.1). A project's repository on a forge: which host, its API, the repository's
-- path there, and the server-side file holding the API token (only the path is stored; the
-- token is read when used and never written anywhere).
--
-- An issue's pull request: requested by its agent (`open_pr`), opened by the forge poller once
-- the run that asked has ended and pushed the branch, then followed (head sha, checks) until
-- it is merged (only through a `pr_merge` approval: `merging`, E9.3) or closed.

CREATE TABLE project_forges (
    project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('github', 'gitlab')),
    api_url    TEXT    NOT NULL,
    repo       TEXT    NOT NULL,
    token_file TEXT    NOT NULL
);

CREATE TABLE issue_prs (
    issue_id        INTEGER PRIMARY KEY REFERENCES issues(id) ON DELETE CASCADE,
    state           TEXT    NOT NULL DEFAULT 'requested'
                    CHECK (state IN ('requested', 'open', 'merging', 'merged', 'closed')),
    number          INTEGER,
    url             TEXT,
    title           TEXT    NOT NULL,
    body            TEXT    NOT NULL,
    head            TEXT    NOT NULL,
    base            TEXT    NOT NULL,
    head_sha        TEXT,
    checks          TEXT    NOT NULL DEFAULT 'none'
                    CHECK (checks IN ('none', 'pending', 'success', 'failure')),
    -- The agent that asked for it: who gets it back when QA or the merge fails.
    author_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    -- The last thing the forge refused, until something succeeds.
    last_error      TEXT,
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((state = 'requested') = (number IS NULL))
);
CREATE INDEX issue_prs_state ON issue_prs (state);
