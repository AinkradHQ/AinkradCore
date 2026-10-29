-- Project presentation and runtime (API minor 18): an icon, a colour (`#rrggbb`), an uploaded
-- logo (content-addressed with the artifacts, as a company's), teams beyond the owner
-- (`extra_team_ids`, a JSON array of team ids in order; `team_id` stays the owner), and the
-- project's runtime limits: runner tags, a cap on parallel runs, a run timeout and how long
-- worktrees are kept. Stored and shown; dispatch does not apply the limits yet.
ALTER TABLE projects ADD COLUMN icon TEXT;
ALTER TABLE projects ADD COLUMN color TEXT;
ALTER TABLE projects ADD COLUMN logo_sha256 TEXT;
ALTER TABLE projects ADD COLUMN extra_team_ids TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(extra_team_ids) AND json_type(extra_team_ids) = 'array');
ALTER TABLE projects ADD COLUMN runner_tags TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(runner_tags) AND json_type(runner_tags) = 'array');
ALTER TABLE projects ADD COLUMN max_parallel_runs INTEGER CHECK (max_parallel_runs >= 1);
ALTER TABLE projects ADD COLUMN run_timeout_secs INTEGER CHECK (run_timeout_secs >= 1);
ALTER TABLE projects ADD COLUMN worktree_keep_days INTEGER CHECK (worktree_keep_days >= 0);

-- A deleted team leaves its projects' lists.
CREATE TRIGGER teams_leave_projects AFTER DELETE ON teams
BEGIN
    UPDATE projects SET extra_team_ids = (SELECT json_group_array(value)
        FROM json_each(projects.extra_team_ids) WHERE value <> OLD.id)
    WHERE extra_team_ids <> '[]';
END;

-- A repo's detected or entered stack ("Swift", "Rust · Node").
ALTER TABLE project_repos ADD COLUMN stack TEXT NOT NULL DEFAULT '';
