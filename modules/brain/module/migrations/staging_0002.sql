-- The semantic step's suggestions for this run (one row). `epoch` makes a late finish of an older
-- step unable to overwrite a newer one. Ids, scores and keywords only, never item text.
CREATE TABLE semantic (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    state TEXT NOT NULL CHECK (state IN ('pending','ready','off')),
    epoch   INTEGER NOT NULL,
    body  TEXT NOT NULL DEFAULT '{}'
);
