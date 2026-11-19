-- Lore E10-2 (D-28): a `.md` file an AI session wrote in its own folder, imported as a note and kept in step
-- with the file. `file_hash` is the sha-256 of the file as last synced in either direction; `dirty` counts
-- saves not yet written back to the file. Holds no text and no secret.
CREATE TABLE lore_session_docs (
    note      TEXT PRIMARY KEY REFERENCES lore_notes (id) ON DELETE CASCADE,
    session   TEXT NOT NULL,
    runner    TEXT NOT NULL,
    path      TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    dirty     INTEGER NOT NULL DEFAULT 0 CHECK (dirty >= 0),
    UNIQUE (session, path)
);
CREATE INDEX lore_session_docs_session ON lore_session_docs (session);
