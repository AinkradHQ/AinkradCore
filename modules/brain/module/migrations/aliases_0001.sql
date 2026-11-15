-- The person's "same project as" answers (`<brain dir>/aliases.db`, encrypted with the brain key):
-- the normalized name of a room -> the name of the project it is. Every later discovery and re-sort
-- files the one as the other.
CREATE TABLE room_aliases (
    from_key   TEXT PRIMARY KEY,
    to_name    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
