CREATE TABLE core_terminals (
    seq INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    id TEXT NOT NULL UNIQUE,
    runner TEXT NOT NULL REFERENCES core_devices(id),
    status TEXT NOT NULL CHECK (status IN ('created', 'running', 'exited', 'reaped')),
    rows INTEGER NOT NULL CHECK (rows BETWEEN 1 AND 1000),
    cols INTEGER NOT NULL CHECK (cols BETWEEN 1 AND 1000),
    output_seq INTEGER NOT NULL DEFAULT 0 CHECK (output_seq >= 0),
    opened_by TEXT REFERENCES core_devices(id),
    created_at TEXT NOT NULL,
    exit_code INTEGER,
    exit_signal TEXT,
    last_activity INTEGER NOT NULL
);
CREATE INDEX core_terminals_runner_status ON core_terminals(runner, status);
