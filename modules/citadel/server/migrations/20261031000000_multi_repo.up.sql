-- Multi-repo projects (E15.16, decision #51). A project has N repositories, in the order agents
-- see them and PRs merge in (#54), one of them primary (the default for an issue). Each holds
-- its own forge (formerly `project_forges`: which host, its API, the repository's path there and
-- the server-side token file, never the token) and its own build, test, lint and format
-- commands. The existing single repo becomes the primary one, named after the project key, with
-- its project's forge folded in. A forge row without a repo (nothing could use it) is dropped.
CREATE TABLE project_repos_new (
    id               INTEGER PRIMARY KEY,
    user_id          INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- A worktree directory name: [A-Za-z0-9._-], not starting with a dot.
    name             TEXT    NOT NULL CHECK (name <> '' AND name NOT GLOB '*[^A-Za-z0-9._-]*'
                                             AND name NOT GLOB '.*'),
    url              TEXT    NOT NULL CHECK (url <> ''),
    default_branch   TEXT    NOT NULL DEFAULT 'main' CHECK (default_branch <> ''),
    position         INTEGER NOT NULL DEFAULT 0,
    is_primary       INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    forge_kind       TEXT    CHECK (forge_kind IN ('github', 'gitlab')),
    forge_api_url    TEXT,
    forge_repo       TEXT,
    forge_token_file TEXT,
    build_cmd        TEXT    NOT NULL DEFAULT '',
    test_cmd         TEXT    NOT NULL DEFAULT '',
    lint_cmd         TEXT    NOT NULL DEFAULT '',
    format_cmd       TEXT    NOT NULL DEFAULT '',
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((forge_kind IS NULL) = (forge_api_url IS NULL)
       AND (forge_kind IS NULL) = (forge_repo IS NULL)
       AND (forge_kind IS NULL) = (forge_token_file IS NULL)),
    UNIQUE (project_id, name),
    UNIQUE (project_id, url)
);
INSERT INTO project_repos_new (user_id, project_id, name, url, default_branch, position,
    is_primary, forge_kind, forge_api_url, forge_repo, forge_token_file, created_at)
SELECT r.user_id, r.project_id, lower(p.key), r.url, r.default_branch, 0, 1, f.kind, f.api_url,
       f.repo, f.token_file, r.created_at
FROM project_repos r JOIN projects p ON p.id = r.project_id
LEFT JOIN project_forges f ON f.project_id = r.project_id;
DROP TABLE project_repos;
ALTER TABLE project_repos_new RENAME TO project_repos;
CREATE UNIQUE INDEX project_repos_one_primary ON project_repos (project_id) WHERE is_primary = 1;
DROP TABLE project_forges;

-- An issue's pull requests, one per repo it touches, all on the issue's one branch name.
-- Existing PRs were on the project's only repo, now its primary.
CREATE TABLE issue_prs_new (
    issue_id        INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    repo_id         INTEGER NOT NULL REFERENCES project_repos(id) ON DELETE CASCADE,
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
    PRIMARY KEY (issue_id, repo_id),
    CHECK ((state = 'requested') = (number IS NULL))
);
INSERT INTO issue_prs_new (issue_id, repo_id, state, number, url, title, body, head, base,
    head_sha, checks, author_agent_id, last_error, updated_at)
SELECT pr.issue_id, r.id, pr.state, pr.number, pr.url, pr.title, pr.body, pr.head, pr.base,
       pr.head_sha, pr.checks, pr.author_agent_id, pr.last_error, pr.updated_at
FROM issue_prs pr JOIN issues i ON i.id = pr.issue_id
JOIN project_repos r ON r.project_id = i.project_id AND r.is_primary = 1;
DROP TABLE issue_prs;
ALTER TABLE issue_prs_new RENAME TO issue_prs;
CREATE INDEX issue_prs_state ON issue_prs (state);
CREATE INDEX issue_prs_repo ON issue_prs (repo_id);
CREATE TRIGGER issue_prs_same_project BEFORE INSERT ON issue_prs
BEGIN
    SELECT RAISE(ABORT, 'repo belongs to another project')
    WHERE (SELECT project_id FROM project_repos WHERE id = NEW.repo_id)
       <> (SELECT project_id FROM issues WHERE id = NEW.issue_id);
END;

-- The repos an issue touches, when not just its project's primary one: set while planning
-- (`approved`), or asked for by its agent mid-task (`requested`) and decided by the team lead
-- or a human (#55). An issue with no approved row touches the primary repo.
CREATE TABLE issue_repos (
    issue_id              INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    repo_id               INTEGER NOT NULL REFERENCES project_repos(id) ON DELETE CASCADE,
    state                 TEXT    NOT NULL DEFAULT 'approved'
                          CHECK (state IN ('requested', 'approved', 'rejected')),
    requested_by_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    -- Why it was asked for, then the decider's reply.
    reason                TEXT,
    PRIMARY KEY (issue_id, repo_id)
);
CREATE INDEX issue_repos_repo ON issue_repos (repo_id);
CREATE TRIGGER issue_repos_same_project BEFORE INSERT ON issue_repos
BEGIN
    SELECT RAISE(ABORT, 'repo belongs to another project')
    WHERE (SELECT project_id FROM project_repos WHERE id = NEW.repo_id)
       <> (SELECT project_id FROM issues WHERE id = NEW.issue_id);
END;
