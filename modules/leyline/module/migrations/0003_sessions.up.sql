-- Leyline Y3-01: one row per host terminal opened through the Core (relayed through a runner).
-- The terminal itself is the Core's own `core_terminals` row; this row names the host and ends with it.
CREATE TABLE leyline_sessions (
    id          TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'ls_'),
    host_id     TEXT NOT NULL REFERENCES leyline_hosts (id) ON DELETE CASCADE,
    terminal    TEXT NOT NULL,
    runner      TEXT NOT NULL,
    principal   TEXT NOT NULL,
    run_id      TEXT,
    started_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ended_at    TEXT,
    end_reason  TEXT CHECK (end_reason IS NULL OR end_reason IN
                    ('exited', 'runner_lost', 'host_key_unknown', 'host_key_changed', 'auth_failed', 'failed')),
    exit_code   INTEGER
);
CREATE INDEX leyline_sessions_host ON leyline_sessions (host_id, started_at);
