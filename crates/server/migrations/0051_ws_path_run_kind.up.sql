-- The canonical workspace (Core 0.10, E15-2): the session's folder under `workspace.root`
-- (`workspace::paths::session_dir`); NULL for a session from before it (legacy, kept on its
-- runner until 0.11).
ALTER TABLE core_agent_sessions ADD COLUMN ws_path TEXT;
-- Run configurations as jobs (E15-3): a `task` starts as a heavy job, a `service` keeps
-- `run.start` on the runner `place_job` picks.
ALTER TABLE core_run_configs ADD COLUMN kind TEXT NOT NULL DEFAULT 'service'
    CHECK (kind IN ('service', 'task'));
