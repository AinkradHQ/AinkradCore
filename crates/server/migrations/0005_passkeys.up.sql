-- Passkey credentials (E1-08, handshake spec §9). A passkey is a device of kind `passkey`,
-- paired by an existing admin device, never self-enrolled; this table holds its WebAuthn
-- credential. `routine_spki` of the device row is the credential's public key as a P-256 SPKI
-- (the SAS is computed over it); `passkey` is the verifier's own record of the credential
-- (webauthn-rs `Passkey`: the COSE key, the sign count and the backup flags), kept as JSON.
-- A credential whose sign count went backwards is revoked here and its device locked.
CREATE TABLE core_passkeys (
    credential_id BLOB    PRIMARY KEY CHECK (length(credential_id) BETWEEN 16 AND 1023),
    device_id     TEXT    NOT NULL UNIQUE REFERENCES core_devices(id),
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    passkey       TEXT    NOT NULL CHECK (json_valid(passkey)),
    sign_count    INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports    TEXT    CHECK (transports IS NULL OR json_valid(transports)),
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at  TEXT,
    revoked_at    TEXT
) WITHOUT ROWID;
