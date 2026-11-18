-- Re-distil and purge (B6-01): one run per room. Ids, states and counts only; no content lands here.
CREATE TABLE brain_redistils (
    id           TEXT PRIMARY KEY,
    room         TEXT NOT NULL REFERENCES brain_rooms(id),
    dry_run      INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
    -- running: reading sources in batches; committing: all read, the one write is next (retried until
    -- it lands); done; failed (3 failures in a row, no local model at the commit, or no progress in
    -- 12 hours; starting it again within 24 hours resumes it); cancelled (by a person, or a dry run a
    -- real run replaced).
    state        TEXT NOT NULL CHECK (state IN ('running', 'committing', 'done', 'failed', 'cancelled')),
    requested_by TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    progress_at  TEXT,                 -- when it last read a source (start, before the first)
    total        INTEGER NOT NULL DEFAULT 0,
    read         INTEGER NOT NULL DEFAULT 0,
    failures     INTEGER NOT NULL DEFAULT 0,
    kept         INTEGER,
    new_facts    INTEGER,
    archived     INTEGER,
    change       TEXT,
    detail       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX brain_redistils_room ON brain_redistils(room, started_at);
-- The run a batch distil belongs to (trigger 'redistil'); NULL for every other distil.
ALTER TABLE brain_distils ADD COLUMN redistil TEXT;
