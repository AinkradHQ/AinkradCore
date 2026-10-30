-- The secrets broker v0 (E2-07, P2.9; threat model T-SEC-1..4). A secret's value is only ever
-- stored sealed (`sealed`: `ops::secretbox` envelope v1, AES-256-GCM under the master key named
-- by `key_id`, a fresh nonce per seal, the associated data binding the name and the version), and
-- only ever leaves the Core through a lease: one runner, one redemption, a short lifetime.
-- `runners` is the secret's scope: the runner device ids that may be leased it (empty: none).
-- `delivery` is how the runner hands it to a session (env, file or askpass; E2-07.2).
CREATE TABLE core_secrets (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name       TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 64
                           AND substr(name, 1, 1) GLOB '[a-z]'
                           AND name NOT GLOB '*[^a-z0-9_.-]*'),
    owner      TEXT    NOT NULL REFERENCES core_devices(id),
    runners    TEXT    NOT NULL DEFAULT '[]'
                       CHECK (json_valid(runners) AND json_type(runners) = 'array'),
    delivery   TEXT    NOT NULL CHECK (delivery IN ('env', 'file', 'askpass')),
    version    INTEGER NOT NULL CHECK (version >= 1),
    key_id     TEXT    NOT NULL CHECK (length(key_id) = 16),
    sealed     BLOB    NOT NULL,
    size       INTEGER NOT NULL CHECK (size >= 1),
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

-- A lease: only the SHA-256 of its `l_…` id is kept. It names one runner device, which alone
-- may redeem it, once, before `expires_at` (unix seconds).
CREATE TABLE core_secret_leases (
    hash       BLOB    PRIMARY KEY CHECK (length(hash) = 32),
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    secret_id  INTEGER NOT NULL REFERENCES core_secrets(id) ON DELETE CASCADE,
    runner     TEXT    NOT NULL REFERENCES core_devices(id),
    expires_at INTEGER NOT NULL,
    used_at    TEXT,
    created_at TEXT    NOT NULL
) WITHOUT ROWID;

CREATE INDEX core_secret_leases_secret ON core_secret_leases (secret_id);
