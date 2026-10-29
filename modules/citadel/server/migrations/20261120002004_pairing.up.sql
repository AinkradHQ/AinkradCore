-- Device pairing (parity API B2, item 7): the admin asks for a 6-character code, the new device
-- trades it, once and before it expires, for its own device key. Only the code's hash is kept.
CREATE TABLE device_pairings (
    code_hash     BLOB    PRIMARY KEY,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,
    used_at       TEXT,
    device_key_id INTEGER REFERENCES device_keys(id) ON DELETE SET NULL
) WITHOUT ROWID;
