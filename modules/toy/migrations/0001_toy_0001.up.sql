-- Every object a module creates starts with `<id>_`; the Core refuses the migration otherwise.
CREATE TABLE toy_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
    body       TEXT NOT NULL CHECK (length(body) <= 4000),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
