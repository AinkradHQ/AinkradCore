-- Lore R2-02: note search. One vector per chunk (a heading's section, or a window of a long one), and the
-- revision each note was last embedded at, so the background job finds what is stale without a save hook.
CREATE TABLE lore_chunks (
    note    TEXT NOT NULL REFERENCES lore_notes (id) ON DELETE CASCADE,
    seq     INTEGER NOT NULL,
    heading TEXT,
    start   INTEGER NOT NULL,   -- byte offsets into the note text at `lore_embedded.rev`
    len     INTEGER NOT NULL,
    model   TEXT NOT NULL,
    vec     BLOB NOT NULL,      -- little-endian f32
    PRIMARY KEY (note, seq)
) WITHOUT ROWID;
CREATE TABLE lore_embedded (
    note  TEXT PRIMARY KEY REFERENCES lore_notes (id) ON DELETE CASCADE,
    rev   INTEGER NOT NULL,
    model TEXT NOT NULL
) WITHOUT ROWID;
