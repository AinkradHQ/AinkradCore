-- Items each source delivered per UTC day, for the Sources screen (read this week, last read). Counts only.
CREATE TABLE brain_read_days (
    device  TEXT NOT NULL,
    kind    TEXT NOT NULL,
    day     TEXT NOT NULL,
    n       INTEGER NOT NULL,
    last_at TEXT NOT NULL,
    PRIMARY KEY (device, kind, day)
) WITHOUT ROWID;
