-- Projects (Core 0.9, P1-01): a named set of git repos that sessions and, later, runs belong to.
-- `slug` is a DNS label (it becomes `<slug>.ainkrad.io`); the reserved names are refused in Rust
-- (`store::projects::RESERVED`). A project is archived, never deleted, so its sessions keep a
-- target. Repo mirrors are held on the Core machine, so a mirror is keyed by its repo alone.
-- `secret_group` and the limits are read by later stories; nothing here creates run tables.
CREATE TABLE core_projects (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    slug         TEXT    NOT NULL UNIQUE CHECK (slug GLOB '[a-z]*' AND slug NOT GLOB '*[^a-z0-9-]*'
                             AND slug NOT GLOB '*-' AND length(slug) BETWEEN 2 AND 40),
    name         TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description  TEXT    NOT NULL DEFAULT '',
    state        TEXT    NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'archived')),
    source       TEXT    NOT NULL CHECK (source IN ('manual', 'github')),
    secret_group INTEGER REFERENCES core_secret_groups(id),
    expose       INTEGER NOT NULL DEFAULT 1 CHECK (expose IN (0, 1)),
    idle_minutes INTEGER NOT NULL DEFAULT 30 CHECK (idle_minutes BETWEEN 5 AND 1440),
    cpu_limit    REAL    NOT NULL DEFAULT 2.0,
    mem_limit_mb INTEGER NOT NULL DEFAULT 2048,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);

CREATE TABLE core_project_repos (
    id             INTEGER PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES core_projects(id) ON DELETE CASCADE,
    name           TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    remote_url     TEXT    NOT NULL,
    default_branch TEXT    NOT NULL,
    is_primary     INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    UNIQUE (project_id, name),
    UNIQUE (project_id, remote_url)
);
CREATE UNIQUE INDEX core_project_repos_one_primary ON core_project_repos (project_id)
    WHERE is_primary = 1;

CREATE TABLE core_project_mirrors (
    repo_id    INTEGER PRIMARY KEY REFERENCES core_project_repos(id) ON DELETE CASCADE,
    head       TEXT,
    fetched_at TEXT,
    error      TEXT
);

ALTER TABLE core_agent_sessions ADD COLUMN project_id INTEGER REFERENCES core_projects(id);
