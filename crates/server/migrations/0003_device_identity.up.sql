-- Device identity (E1-07.2, handshake spec §3, §7, §11): bearer device keys are gone. A device
-- is a P-256 public key it generated itself; the Core never sees a private key and stores no
-- secret a device could be impersonated with. Nothing is carried over: bearer keys have no
-- legacy path (spec §1, P1.4).
DROP TABLE device_pairings;
DROP TABLE device_keys;

-- One row per device: a native client or CLI (`device`), a runner (`runner`), or a browser
-- passkey (`passkey`, E1-08). `seq` is the local row number (audit rows name it: an audit
-- entity id is an integer); `id` is the random `d_…` id every API and header uses. Scopes are
-- a JSON array of names (E1-09 enforces them). A revoked row stays, so its history stays
-- visible, and keeps the device out of `bootstrap` (§7.3).
CREATE TABLE core_devices (
    seq          INTEGER PRIMARY KEY,
    id           TEXT    NOT NULL UNIQUE CHECK (id GLOB 'd_*' AND length(id) = 28),
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    kind         TEXT    NOT NULL CHECK (kind IN ('device', 'runner', 'passkey')),
    name         TEXT    NOT NULL CHECK (name <> ''),
    -- The routine key (signs every request) and the optional step-up key (E1-09), as 91-byte
    -- SPKIs; `fingerprint` is base64url(SHA-256(routine_spki)).
    routine_spki BLOB    NOT NULL UNIQUE CHECK (length(routine_spki) = 91),
    fingerprint  TEXT    NOT NULL UNIQUE CHECK (length(fingerprint) = 43),
    stepup_spki  BLOB    CHECK (stepup_spki IS NULL OR length(stepup_spki) = 91),
    platform     TEXT,
    -- Reported by the client, a claim (§3).
    key_storage  TEXT    CHECK (key_storage IN
                            ('secure_enclave', 'strongbox', 'tee', 'tpm', 'software')),
    scopes       TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(scopes) AND json_type(scopes) = 'array'),
    -- `pending` until a pairing is approved; `locked` for a cloned passkey (E1-08).
    status       TEXT    NOT NULL CHECK (status IN
                            ('pending', 'active', 'rejected', 'expired', 'locked')),
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT,
    revoked_at   TEXT,
    -- Where its pushes go (E10.4): an APNs token, and whether it is a development build's.
    push_token   TEXT
                 CHECK (push_token IS NULL OR (length(push_token) BETWEEN 32 AND 200
                                               AND push_token NOT GLOB '*[^0-9a-f]*')),
    push_sandbox INTEGER NOT NULL DEFAULT 0 CHECK (push_sandbox IN (0, 1))
);

-- A pairing (§7): created by an approver device (or `bootstrap` on the host), claimed once by
-- a new device with the typed code or the QR secret, then approved or rejected. Only the
-- hashes of the code and the secret are kept; a pairing is looked up by hash. The name, kind
-- and scopes are bound here, never taken from the claimant.
CREATE TABLE core_pairings (
    id          TEXT    PRIMARY KEY CHECK (id GLOB 'p_*' AND length(id) = 28),
    user_id     INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    code_hash   BLOB    NOT NULL UNIQUE CHECK (length(code_hash) = 32),
    secret_hash BLOB    NOT NULL UNIQUE CHECK (length(secret_hash) = 32),
    kind        TEXT    NOT NULL CHECK (kind IN ('device', 'runner', 'passkey')),
    name        TEXT    NOT NULL CHECK (name <> ''),
    scopes      TEXT    NOT NULL CHECK (json_valid(scopes) AND json_type(scopes) = 'array'),
    -- The device that created it, or NULL for the host's `bootstrap` and `recover`.
    created_by  TEXT    REFERENCES core_devices(id),
    -- 0: a pairing from a device; 1: the host's first-device `bootstrap`; 2: the host's
    -- `recover` (§12). 1 and 2 are claimable only over the host's own socket.
    bootstrap   INTEGER NOT NULL DEFAULT 0 CHECK (bootstrap IN (0, 1, 2)),
    created_at  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'live' CHECK (status IN
                           ('live', 'claimed', 'approved', 'rejected', 'expired', 'burned')),
    -- The claimant, once claimed, and the SAS both screens show.
    device_id   TEXT    UNIQUE REFERENCES core_devices(id),
    sas         TEXT,
    decided_by  TEXT,
    decided_at  TEXT,
    CHECK (status <> 'live' OR device_id IS NULL)
) WITHOUT ROWID;

-- Persisted failure counters and lockouts (§11): by address (`ip:…`) and by address and
-- claimed device (`ipdev:…`), never by device alone. Only failures write. Times are unix
-- seconds.
CREATE TABLE core_auth_limits (
    key          TEXT    PRIMARY KEY,
    fails        INTEGER NOT NULL,
    window_start INTEGER NOT NULL,
    locked_until INTEGER NOT NULL DEFAULT 0,
    strikes      INTEGER NOT NULL DEFAULT 0,
    strikes_at   INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
