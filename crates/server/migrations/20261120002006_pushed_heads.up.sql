-- The sha each issue branch was last pushed at, by any run (`branch_pushed`), per repo. The
-- runner's next push of that branch leases on it (`--force-with-lease`), so a rewritten branch
-- lands only when the remote still holds the head this server confirmed. Unlike
-- `issue_prs.pushed_sha` (cleared when a PR is requested again), it is kept for the branch's life.
CREATE TABLE issue_pushed_heads (
    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    repo_id  INTEGER NOT NULL REFERENCES project_repos(id) ON DELETE CASCADE,
    sha      TEXT    NOT NULL,
    PRIMARY KEY (issue_id, repo_id)
);
