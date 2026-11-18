-- Project runs (Core 0.9, P5-03): one row per start of a project on a runner. The partial unique
-- index is the double-start guard: a project has at most one live run (`starting`, `running` or
-- `stopping`), whatever races to start it. A finished row is kept as history. `stop_reason` is
-- why it ended (or, while `stopping`, why it is being stopped); `error` says what went wrong,
-- redacted, for `failed` and `runner_lost`. `start_failed` is a start that never reached running
-- (the plan's list had no word for it).
CREATE TABLE core_project_runs (
    id               TEXT    PRIMARY KEY,
    project_id       INTEGER NOT NULL REFERENCES core_projects(id),
    spec_version     INTEGER NOT NULL,
    runner           TEXT    NOT NULL,
    state            TEXT    NOT NULL
                     CHECK (state IN ('starting', 'running', 'stopping', 'stopped', 'failed')),
    stop_reason      TEXT
                     CHECK (stop_reason IN ('user', 'idle', 'crash', 'runner_lost', 'replaced',
                                            'start_failed')),
    error            TEXT,
    started_by       TEXT    NOT NULL,
    started_at       TEXT    NOT NULL,
    stopped_at       TEXT,
    last_activity_at TEXT
);
CREATE UNIQUE INDEX core_project_runs_one_live ON core_project_runs (project_id)
    WHERE state IN ('starting', 'running', 'stopping');
CREATE INDEX core_project_runs_by_project ON core_project_runs (project_id, started_at);
