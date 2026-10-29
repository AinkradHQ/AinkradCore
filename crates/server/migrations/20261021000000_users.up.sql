-- Convention (#18): every domain table carries
--   user_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id)
-- so roles and more users can come later without a data migration.
-- Today there is a single admin user (id 1).
CREATE TABLE users (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO users (id, name) VALUES (1, 'admin');
