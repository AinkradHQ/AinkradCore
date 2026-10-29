DROP TABLE core_auth_limits;
DROP TABLE core_pairings;
DROP TABLE core_devices;

CREATE TABLE device_keys (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name         TEXT    NOT NULL,
    key_hash     BLOB    NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT,
    revoked_at   TEXT,
    push_token   TEXT
                 CHECK (push_token IS NULL OR (length(push_token) BETWEEN 32 AND 200
                                               AND push_token NOT GLOB '*[^0-9a-f]*')),
    push_sandbox INTEGER NOT NULL DEFAULT 0 CHECK (push_sandbox IN (0, 1))
);

CREATE TABLE device_pairings (
    code_hash     BLOB    PRIMARY KEY,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,
    used_at       TEXT,
    device_key_id INTEGER REFERENCES device_keys(id) ON DELETE SET NULL
) WITHOUT ROWID;
