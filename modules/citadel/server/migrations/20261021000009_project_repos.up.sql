-- A project's git repository (E3.7): runs on its issues work in a git worktree per issue,
-- cut from `default_branch`. `url` never holds credentials; runners authenticate through
-- their own GIT_ASKPASS. A project without a row has no repo: its runs get a scratch dir.
CREATE TABLE project_repos (
    project_id     INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    url            TEXT    NOT NULL CHECK (url <> ''),
    default_branch TEXT    NOT NULL DEFAULT 'main' CHECK (default_branch <> ''),
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
