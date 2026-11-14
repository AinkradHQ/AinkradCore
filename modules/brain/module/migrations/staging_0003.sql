-- The AI tidy of this run's proposal (one row): its changes, counts and the proposal as it was
-- before (item rooms and marks, proposal rows), so Undo restores it exactly. Ids only, never text.
CREATE TABLE tidy (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    state    TEXT NOT NULL CHECK (state IN ('applied','undone')),
    summary  TEXT NOT NULL,
    changes  TEXT NOT NULL,
    snapshot TEXT NOT NULL
);
