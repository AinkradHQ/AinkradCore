-- Leyline Y3-02: terminal recordings. One row per recorded session; the bytes live in
-- `<data>/leyline/recordings/<session>.cast.age` (encrypted blocks, see `record.rs`). Recording is
-- opt-in per host (`leyline_hosts.record`, off by default): no row and no file exist for a session
-- of a host that has it off.
CREATE TABLE leyline_recordings (
    session     TEXT PRIMARY KEY REFERENCES leyline_sessions (id) ON DELETE CASCADE,
    host_id     TEXT NOT NULL,
    file        TEXT NOT NULL CHECK (file NOT GLOB '*[^A-Za-z0-9._]*' AND file LIKE 'ls\_%.cast.age' ESCAPE '\'),
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    bytes       INTEGER NOT NULL DEFAULT 0,
    -- A person paused it (`POST /sessions/{session}/recording/pause`); output is not written.
    paused      INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1))
);
CREATE INDEX leyline_recordings_started ON leyline_recordings (started_at);

-- The age identity that opens recordings, sealed under the Core's master key (`SecretBox`); the
-- recipient (public) is what the writer encrypts to. One row, made on first use.
CREATE TABLE leyline_recording_key (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    recipient   TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    sealed      BLOB NOT NULL
);
