-- The AI tidy may decline (`declined`: it was not confident, nothing changed), and the run keeps a
-- copy of the person's "same project as" aliases so the employer guard reads them. Names only.
CREATE TABLE tidy_new (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    state    TEXT NOT NULL CHECK (state IN ('applied','undone','declined')),
    summary  TEXT NOT NULL,
    changes  TEXT NOT NULL,
    snapshot TEXT NOT NULL
);
INSERT INTO tidy_new SELECT * FROM tidy;
DROP TABLE tidy;
ALTER TABLE tidy_new RENAME TO tidy;
CREATE TABLE aliases (
    from_key TEXT PRIMARY KEY,
    to_name  TEXT NOT NULL
);
