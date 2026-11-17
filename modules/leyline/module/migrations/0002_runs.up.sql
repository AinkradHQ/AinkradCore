-- Leyline Y4-01: one row per gated execution (single or fleet) and one per host in it. The command
-- text, when there is one, is stored redacted and cut; output arrives with Y4-02.
CREATE TABLE leyline_runs (
    id          TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'lr_'),
    command_id  TEXT,
    adhoc       TEXT,
    action      TEXT NOT NULL,
    principal   TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('waiting_approval', 'running', 'done', 'cancelled', 'denied')),
    approval    TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ended_at    TEXT
);

CREATE TABLE leyline_run_hosts (
    run_id      TEXT NOT NULL REFERENCES leyline_runs (id) ON DELETE CASCADE,
    host_id     TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('queued', 'needs_approval', 'running', 'ok', 'failed', 'refused', 'skipped')),
    step        INTEGER,
    exit_code   INTEGER,
    duration_ms INTEGER,
    output      TEXT,
    PRIMARY KEY (run_id, host_id)
);
