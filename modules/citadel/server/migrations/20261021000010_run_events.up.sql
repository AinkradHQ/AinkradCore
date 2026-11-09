-- A run's transcript (E3.9): sequenced chunks from the runner holding the run's lease,
-- redacted by the runner and again by the server before they are written. `seq` counts from
-- 1 per run; a resent chunk is ignored by the unique key, so the transcript is ordered and
-- idempotent. `kind` is the chunk's `type`.
CREATE TABLE run_events (
    id      INTEGER PRIMARY KEY,
    run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq     INTEGER NOT NULL CHECK (seq > 0),
    at      TEXT    NOT NULL,
    kind    TEXT    NOT NULL CHECK (kind <> ''),
    payload TEXT    NOT NULL CHECK (json_valid(payload)),
    UNIQUE (run_id, seq)
);
