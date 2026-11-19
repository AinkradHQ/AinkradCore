DROP INDEX core_project_runs_one_live;
CREATE UNIQUE INDEX core_project_runs_one_live ON core_project_runs (project_id)
    WHERE state IN ('starting', 'running', 'stopping');
