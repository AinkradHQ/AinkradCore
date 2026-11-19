-- Core 0.10 (E11-3): one live run per project AND configuration, so a dev server, a worker and the
-- tests can run at once. A run started without a configuration still counts as configuration 0:
-- the project's setup as saved.
DROP INDEX core_project_runs_one_live;
CREATE UNIQUE INDEX core_project_runs_one_live ON core_project_runs (project_id, ifnull(config_id, 0))
    WHERE state IN ('starting', 'running', 'stopping');
