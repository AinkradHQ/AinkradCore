ALTER TABLE core_project_runs DROP COLUMN environment;
ALTER TABLE core_project_runs DROP COLUMN config_id;
DROP TABLE core_run_vars;
DROP TABLE core_run_configs;
DROP TABLE core_run_envs;
