-- The queue of room Overview writes: one row per room, one batch at a time, one room at a time.
CREATE TABLE brain_overview_queue (
    room         TEXT PRIMARY KEY,
    batch        TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','done','failed')),
    attempt      INTEGER NOT NULL DEFAULT 1,
    session      TEXT,
    requested_by TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
