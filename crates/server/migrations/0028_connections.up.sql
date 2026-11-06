-- Connections (C1; design 2026-11-06-core-connections-design §2, §4). A connection links the Core to an
-- outside service (a kind: `github`, `jira`) with one credential. The credential is sealed in
-- `core_connection_secrets` and is never read back by any API. Every table carries `user_id` (the workspace
-- owner whose connections these are). Additive only.
-- AUTOINCREMENT: an id (and the sealing label built from it) is never reused after a delete.
-- `status` is the S3 health state (active, cooling, limited, unhealthy, disabled); `disabled` is the admin's
-- own switch. `auth_pending` is an upstream auth failure not yet confirmed by a test: it never disables.
CREATE TABLE core_connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    kind            TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 32),
    name            TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    label           TEXT    NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
    identity        TEXT    CHECK (identity IS NULL OR length(identity) <= 200),
    auth_method     TEXT    NOT NULL CHECK (auth_method IN ('oauth', 'app_install', 'token')),
    status          TEXT    NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'cooling', 'limited', 'unhealthy', 'disabled')),
    state_reason    TEXT,
    state_until     TEXT    CHECK (state_until IS NULL OR julianday(state_until) IS NOT NULL),
    fail_streak     INTEGER NOT NULL DEFAULT 0,
    backoff_secs    INTEGER NOT NULL DEFAULT 0,
    fail_since      TEXT,
    auth_pending    INTEGER NOT NULL DEFAULT 0 CHECK (auth_pending IN (0, 1)),
    auth_tries      INTEGER NOT NULL DEFAULT 0,
    last_success_at TEXT,
    last_tested_at  TEXT,
    created_by      TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    UNIQUE (user_id, kind, name)
);

-- Sealed material (JSON of access and refresh token, AES-256-GCM under the master key, label
-- `core.connection:<id>:v<version>`). `expires_at` is the access token's expiry, not secret.
CREATE TABLE core_connection_secrets (
    connection_id INTEGER PRIMARY KEY REFERENCES core_connections(id) ON DELETE CASCADE,
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    version       INTEGER NOT NULL CHECK (version >= 1),
    key_id        TEXT    NOT NULL,
    sealed        BLOB    NOT NULL,
    expires_at    TEXT,
    updated_at    TEXT    NOT NULL
);

-- Who may use a connection: a user (id), a role (`admin`, `member`) or an agent (opaque id), which
-- capabilities (JSON array; read-only unless the grant names write ones) and which resources (JSON object of
-- the kind's limit keys to lists; empty: unrestricted).
CREATE TABLE core_connection_grants (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    connection_id INTEGER NOT NULL REFERENCES core_connections(id) ON DELETE CASCADE,
    grantee_kind  TEXT    NOT NULL CHECK (grantee_kind IN ('user', 'role', 'agent')),
    grantee       TEXT    NOT NULL CHECK (length(grantee) BETWEEN 1 AND 64),
    capabilities  TEXT    NOT NULL,
    limits        TEXT    NOT NULL DEFAULT '{}',
    created_by    TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    UNIQUE (connection_id, grantee_kind, grantee)
);

-- Where a connection applies, per kind: the workspace default (`scope_ref` ''), a project or repo, an agent,
-- a session. One binding per (user, kind, scope).
CREATE TABLE core_connection_bindings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    kind          TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 32),
    scope_kind    TEXT    NOT NULL CHECK (scope_kind IN ('workspace', 'project', 'agent', 'session')),
    scope_ref     TEXT    NOT NULL CHECK (length(scope_ref) <= 128),
    connection_id INTEGER NOT NULL REFERENCES core_connections(id) ON DELETE CASCADE,
    created_by    TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    UNIQUE (user_id, kind, scope_kind, scope_ref),
    CHECK ((scope_kind = 'workspace') = (scope_ref = ''))
);

CREATE INDEX core_connection_grants_connection ON core_connection_grants (connection_id);
CREATE INDEX core_connection_bindings_connection ON core_connection_bindings (connection_id);
