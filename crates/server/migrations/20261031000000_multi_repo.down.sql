-- Back to one repo per project: each project keeps its primary repo (and its forge) and the PRs
-- on it; other repos, their PRs and issues' repo choices go.
DROP TABLE issue_repos;

CREATE TABLE issue_prs_old (
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
    author_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    last_error      TEXT,
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((state = 'requested') = (number IS NULL))
);
INSERT INTO issue_prs_old (issue_id, state, number, url, title, body, head, base, head_sha,
    checks, author_agent_id, last_error, updated_at)
SELECT pr.issue_id, pr.state, pr.number, pr.url, pr.title, pr.body, pr.head, pr.base,
       pr.head_sha, pr.checks, pr.author_agent_id, pr.last_error, pr.updated_at
FROM issue_prs pr JOIN project_repos r ON r.id = pr.repo_id AND r.is_primary = 1;
DROP TABLE issue_prs;
ALTER TABLE issue_prs_old RENAME TO issue_prs;
CREATE INDEX issue_prs_state ON issue_prs (state);

CREATE TABLE project_forges (
    project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('github', 'gitlab')),
    api_url    TEXT    NOT NULL,
    repo       TEXT    NOT NULL,
    token_file TEXT    NOT NULL
);
INSERT INTO project_forges (project_id, kind, api_url, repo, token_file)
SELECT project_id, forge_kind, forge_api_url, forge_repo, forge_token_file FROM project_repos
WHERE is_primary = 1 AND forge_kind IS NOT NULL;

CREATE TABLE project_repos_old (
    project_id     INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    url            TEXT    NOT NULL CHECK (url <> ''),
    default_branch TEXT    NOT NULL DEFAULT 'main' CHECK (default_branch <> ''),
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO project_repos_old (project_id, user_id, url, default_branch, created_at)
SELECT project_id, user_id, url, default_branch, created_at FROM project_repos
WHERE is_primary = 1;
DROP TABLE project_repos;
ALTER TABLE project_repos_old RENAME TO project_repos;
