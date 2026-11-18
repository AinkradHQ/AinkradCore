-- Leyline Y5-02: alerts in the bell. One OPEN alert per host and kind (the unique index); resolving
-- stamps `resolved_at` and keeps the row as history. No remote text: `detail` stays NULL for now.
CREATE TABLE leyline_alerts (
    id          INTEGER PRIMARY KEY,
    host_id     TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('down', 'disk', 'memory', 'failed_units', 'host_key_changed')),
    opened_at   TEXT NOT NULL,
    resolved_at TEXT,
    detail      TEXT
);
CREATE UNIQUE INDEX leyline_alerts_one_open ON leyline_alerts (host_id, kind) WHERE resolved_at IS NULL;
