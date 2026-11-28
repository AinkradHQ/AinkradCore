-- Project-level variables of a run environment (API 112): laid over the project's run spec when it
-- starts with no run configuration (and under a configuration's own variables when it has one). Same
-- shape and rules as `core_run_vars`: a plain value or the name of one of the project's secrets,
-- never both.
CREATE TABLE core_run_env_vars (
    project_id INTEGER NOT NULL REFERENCES core_projects(id),
    env        TEXT    NOT NULL,
    key        TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
    value      TEXT,
    secret     TEXT,
    PRIMARY KEY (project_id, env, key),
    CHECK ((value IS NULL) != (secret IS NULL))
);
