-- Leyline Y5-01: agentless health samples. One per minute for a day, then 5-minute averages
-- (`rolled = 1`) for 30 days, moved and pruned by the hourly rollup job. Numbers only, no remote
-- text. No foreign key: the rollup sweeps the rows of a deleted host.
CREATE TABLE leyline_health_samples (
    host_id      TEXT NOT NULL,
    at           INTEGER NOT NULL,
    up           INTEGER NOT NULL CHECK (up IN (0, 1)),
    latency_ms   INTEGER,
    load1        REAL,
    cpus         INTEGER,
    mem_pct      REAL,
    disk_pct     REAL,
    failed_units INTEGER,
    rolled       INTEGER NOT NULL DEFAULT 0 CHECK (rolled IN (0, 1)),
    PRIMARY KEY (host_id, at)
) WITHOUT ROWID;
