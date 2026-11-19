-- Leyline E8: reachability. Every few minutes the Core connects to a host's address and port and reads its
-- SSH banner: no login, no key. One row per host: how it answered last, and when it last answered at all.
CREATE TABLE leyline_reach (
    host_id    TEXT PRIMARY KEY,
    up         INTEGER NOT NULL CHECK (up IN (0, 1)),
    latency_ms INTEGER,
    checked_at INTEGER NOT NULL,
    seen_at    INTEGER
) WITHOUT ROWID;

-- Leyline E8: how "Make runner" on a host stands, for the host page (installing, failed with a reason, paired).
CREATE TABLE leyline_runner_install (
    host_id TEXT PRIMARY KEY,
    state   TEXT NOT NULL CHECK (state IN ('installing', 'failed', 'paired')),
    mode    TEXT CHECK (mode IN ('system', 'user')),
    reason  TEXT,
    at      INTEGER NOT NULL
) WITHOUT ROWID;
