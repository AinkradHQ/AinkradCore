-- Run configurations and environments (Core 0.10, E11-3). A configuration is a named way to run a
-- project (command, folder, port, runner choice) that is laid over one service of the project's
-- run spec at start. An environment (Development, Staging, ...) is a name per project; the
-- variables of a configuration are kept per environment. A variable is a plain value or a
-- reference to one of the project's secrets (`secret` = the secret's name in the project); the
-- value of a secret is never stored here. A start remembers the configuration and environment.
CREATE TABLE core_run_envs (
    project_id INTEGER NOT NULL REFERENCES core_projects(id),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 40),
    position   INTEGER NOT NULL,
    PRIMARY KEY (project_id, name)
);
CREATE TABLE core_run_configs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES core_projects(id),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    command    TEXT    NOT NULL CHECK (length(command) BETWEEN 1 AND 512),
    workdir    TEXT    NOT NULL DEFAULT '',
    runner     TEXT    NOT NULL DEFAULT 'automatic',
    service    TEXT,
    port       INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    restart    INTEGER NOT NULL DEFAULT 0 CHECK (restart IN (0, 1)),
    position   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL,
    UNIQUE (project_id, name)
);
CREATE TABLE core_run_vars (
    config_id INTEGER NOT NULL REFERENCES core_run_configs(id),
    env       TEXT    NOT NULL,
    key       TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
    value     TEXT,
    secret    TEXT,
    PRIMARY KEY (config_id, env, key),
    CHECK ((value IS NULL) != (secret IS NULL))
);
ALTER TABLE core_project_runs ADD COLUMN config_id INTEGER;
ALTER TABLE core_project_runs ADD COLUMN environment TEXT;
