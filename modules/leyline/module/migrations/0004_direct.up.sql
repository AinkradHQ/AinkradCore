-- Leyline Y6-01: one row per Mac-direct lease (an ssh-agent in a runner, bound to one host).
-- Public data only: where the socket is, who asked, how it ended. No key, lease or fingerprint of a key.
CREATE TABLE leyline_direct (
    id           TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'ld_'),
    host_id      TEXT NOT NULL REFERENCES leyline_hosts (id) ON DELETE CASCADE,
    runner       TEXT NOT NULL,
    principal    TEXT NOT NULL,
    run_id       TEXT,
    started_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT NOT NULL,
    expires_unix INTEGER NOT NULL,
    socket       TEXT,
    ended_at     TEXT,
    end_reason   TEXT CHECK (end_reason IS NULL OR end_reason IN ('revoked', 'expired', 'failed')),
    signatures   INTEGER
);
-- One open lease per host, decided by the table, not by a race between two requests.
CREATE UNIQUE INDEX leyline_direct_open ON leyline_direct (host_id) WHERE ended_at IS NULL;
