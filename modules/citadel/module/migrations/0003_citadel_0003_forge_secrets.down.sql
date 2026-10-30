DROP TABLE IF EXISTS citadel_forge_hosts;
ALTER TABLE citadel_project_linear RENAME COLUMN secret TO token_file;
ALTER TABLE citadel_project_repos RENAME COLUMN forge_secret TO forge_token_file;
