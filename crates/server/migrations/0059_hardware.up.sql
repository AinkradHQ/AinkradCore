-- Runners as hardware (Core 0.10, E15-1). The Core host's built-in runner, This Mac and remote
-- runners are hardware the Core places AI sessions and heavy jobs on.
-- A device's preferences: paused until a time (NULL: not paused; '9999-12-31T00:00:00.000Z' for
-- indefinitely) and its job slots (NULL: what the runner reports).
CREATE TABLE core_hardware_prefs (
    device_id    TEXT    PRIMARY KEY REFERENCES core_devices(id),
    paused_until TEXT,
    job_slots    INTEGER CHECK (job_slots IS NULL OR job_slots BETWEEN 1 AND 256)
);
-- Heavy jobs (E15-3): a command taken from a Core terminal or an AI sandbox, a task run
-- configuration, run where `place_job` put it. `argv` is a JSON array of strings; `place_reason`
-- is `core`, `overflow`, `runner`, `this_mac`, `pinned` or `core_no_fit:<missing>`; `tier` the
-- decision step that made it heavy (`rule`, `history`, `decision`) or `config` for a task config.
CREATE TABLE core_hw_jobs (
    id            TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 3 AND 64 AND id GLOB 'j_*'
                              AND substr(id, 3) NOT GLOB '*[^a-z0-9]*'),
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id    INTEGER REFERENCES core_projects(id),
    session_id    TEXT,
    terminal_id   TEXT,
    run_config_id INTEGER REFERENCES core_run_configs(id),
    argv          TEXT    NOT NULL CHECK (json_valid(argv) AND json_type(argv) = 'array'),
    cwd_rel       TEXT    NOT NULL DEFAULT '',
    device_id     TEXT    NOT NULL REFERENCES core_devices(id),
    place_reason  TEXT    NOT NULL CHECK (place_reason IN ('core', 'overflow', 'runner', 'this_mac', 'pinned')
                              OR place_reason GLOB 'core_no_fit:*'),
    tier          TEXT    NOT NULL CHECK (tier IN ('rule', 'history', 'decision', 'config')),
    state         TEXT    NOT NULL
                          CHECK (state IN ('queued', 'syncing', 'running', 'ended', 'failed', 'cancelled', 'lost')),
    exit_code     INTEGER,
    signal        TEXT,
    bytes_in      INTEGER NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    bytes_out     INTEGER NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    conflicts     INTEGER NOT NULL DEFAULT 0 CHECK (conflicts >= 0),
    created_at    TEXT    NOT NULL,
    started_at    TEXT,
    ended_at      TEXT,
    duration_ms   INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0)
);
CREATE INDEX core_hw_jobs_live ON core_hw_jobs (device_id) WHERE state IN ('queued', 'syncing', 'running');
CREATE INDEX core_hw_jobs_project ON core_hw_jobs (project_id, created_at);
CREATE INDEX core_hw_jobs_session ON core_hw_jobs (session_id) WHERE session_id IS NOT NULL;
-- How long a command takes in a project (E15-3 tier 2): `cmd_key` is the program plus its first
-- two non-flag arguments.
CREATE TABLE core_cmd_history (
    project_id INTEGER NOT NULL REFERENCES core_projects(id),
    cmd_key    TEXT    NOT NULL CHECK (length(cmd_key) BETWEEN 1 AND 256),
    runs       INTEGER NOT NULL DEFAULT 0 CHECK (runs >= 0),
    p50_ms     INTEGER NOT NULL DEFAULT 0 CHECK (p50_ms >= 0),
    last_ms    INTEGER NOT NULL DEFAULT 0 CHECK (last_ms >= 0),
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (project_id, cmd_key)
);
-- The tree each device's warm cache of a project was last synced to (E15-2).
CREATE TABLE core_hw_cache (
    device_id  TEXT    NOT NULL REFERENCES core_devices(id),
    project_id INTEGER NOT NULL REFERENCES core_projects(id),
    tree_hash  BLOB    NOT NULL CHECK (length(tree_hash) = 32),
    synced_at  TEXT    NOT NULL,
    PRIMARY KEY (device_id, project_id)
);
-- Why the Core placed a session where it did (`core`, `overflow`, `pinned`); NULL for one placed
-- before E15.
ALTER TABLE core_agent_sessions ADD COLUMN place_reason TEXT
    CHECK (place_reason IS NULL OR place_reason IN ('core', 'overflow', 'runner', 'this_mac', 'pinned'));
