-- Project run specs (Core 0.9, P4-01): what a project runs, as JSON validated in Rust
-- (`store::run_specs`). Versioned: a save is a new row, never an update, so a run can name the
-- exact spec it started from. Projects are archived, never deleted; the cascade is for tests.
CREATE TABLE core_project_run_specs (
    project_id INTEGER NOT NULL REFERENCES core_projects(id) ON DELETE CASCADE,
    version    INTEGER NOT NULL CHECK (version >= 1),
    spec       TEXT    NOT NULL CHECK (json_valid(spec)),
    origin     TEXT    NOT NULL CHECK (origin IN ('manual', 'compose', 'package_json', 'makefile', 'run_sh')),
    created_by TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    PRIMARY KEY (project_id, version)
);
