-- Leyline Y1-01: hosts, pinned host keys, project attachments, key metadata. Every object starts with
-- `leyline_` (the Core refuses the migration otherwise). No private key, password or passphrase is
-- ever stored here: `leyline_keys.secret` only NAMES a `core_secrets` row (sealed by Y1-02).
--
-- The CHECKs on address, username and port are the second layer of the same rules as `valid.rs`
-- (argv / `-o ProxyCommand=` injection guards): the API refuses first, the table refuses anything
-- that reaches it another way.

CREATE TABLE leyline_keys (
    id          TEXT PRIMARY KEY CHECK (substr(id, 1, 2) = 'k_'),
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(name) BETWEEN 1 AND 64 AND name = trim(name)),
    algo        TEXT NOT NULL CHECK (algo IN ('ed25519', 'ecdsa-p256', 'ecdsa-p384', 'rsa')),
    public_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    secret      TEXT NOT NULL,
    origin      TEXT NOT NULL CHECK (origin IN ('generated', 'imported')),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE leyline_hosts (
    id          TEXT PRIMARY KEY CHECK (substr(id, 1, 2) = 'h_'),
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(name) BETWEEN 1 AND 64 AND name = trim(name)),
    address     TEXT NOT NULL CHECK (length(address) BETWEEN 1 AND 255
                                     AND substr(address, 1, 1) <> '-'
                                     AND address NOT GLOB '*[^A-Za-z0-9.:%_-]*'),
    port        INTEGER NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    username    TEXT NOT NULL CHECK (length(username) BETWEEN 1 AND 32
                                     AND substr(username, 1, 1) <> '-'
                                     AND username NOT GLOB '*[^A-Za-z0-9._-]*'),
    key_id      TEXT REFERENCES leyline_keys (id),
    jump_chain  TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(jump_chain) AND json_array_length(jump_chain) <= 3),
    via_runner  TEXT CHECK (via_runner IS NULL OR (substr(via_runner, 1, 2) = 'd_'
                                                   AND length(via_runner) <= 40
                                                   AND via_runner NOT GLOB '*[^A-Za-z0-9_-]*')),
    group_name  TEXT CHECK (group_name IS NULL OR (length(group_name) BETWEEN 1 AND 64 AND group_name = trim(group_name))),
    tags        TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags) AND json_array_length(tags) <= 20),
    ai_rule     TEXT NOT NULL DEFAULT 'ask' CHECK (ai_rule IN ('read_only', 'ask', 'allowed')),
    record      TEXT NOT NULL DEFAULT 'off' CHECK (record IN ('off', 'on')),
    health      INTEGER NOT NULL DEFAULT 1 CHECK (health IN (0, 1)),
    runner_device TEXT,
    os          TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Known hosts, per host (a jump hop is a host too). Data only in Y1-01: trust flows are Y3-01.
CREATE TABLE leyline_host_keys (
    host_id     TEXT NOT NULL REFERENCES leyline_hosts (id) ON DELETE CASCADE,
    algo        TEXT NOT NULL,
    key_b64     TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('trusted', 'seen', 'replaced')),
    trusted_by  TEXT,
    first_seen  TEXT NOT NULL,
    trusted_at  TEXT,
    PRIMARY KEY (host_id, fingerprint)
);

-- project = core_projects.id as text: no foreign key into a Core table.
CREATE TABLE leyline_project_hosts (
    project     TEXT NOT NULL,
    host_id     TEXT NOT NULL REFERENCES leyline_hosts (id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('production', 'staging', 'development', 'other')),
    PRIMARY KEY (project, host_id)
);
