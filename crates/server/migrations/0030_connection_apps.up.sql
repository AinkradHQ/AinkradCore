-- Connection apps (C5; design 2026-11-06-core-connections-design §6, decision 1). The OAuth app registrations Ainkrad
-- owns (GitHub client id, Atlassian client id and secret, the GitHub App's id and private key) are strings, and the
-- settings are integers only, so they live here, one sealed row per (workspace, kind, field), under the master key,
-- label `core.connection_app:<user>:<kind>:<field>:v<version>`. No API returns a value; `configured` says only that all
-- the fields a kind needs are there. Rotated with the other sealed tables, wiped from an export.
CREATE TABLE core_connection_apps (
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    kind       TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 32),
    field      TEXT    NOT NULL CHECK (length(field) BETWEEN 1 AND 32),
    version    INTEGER NOT NULL CHECK (version >= 1),
    key_id     TEXT    NOT NULL,
    sealed     BLOB    NOT NULL,
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (user_id, kind, field)
);

-- The GitHub App installation a connection's token is minted for (`app_install` connections), so a token that is
-- near its end can be minted again. NULL for every other connection. An id is no secret.
ALTER TABLE core_connections ADD COLUMN installation_id INTEGER CHECK (installation_id IS NULL OR installation_id > 0);

-- A GitHub App installation belongs to the first workspace that uses it (`account` is the GitHub account it is
-- installed on, as the App API says): another workspace cannot connect through it. The claim outlives the
-- connection that made it.
CREATE TABLE core_installation_claims (
    installation_id INTEGER PRIMARY KEY CHECK (installation_id > 0),
    user_id         INTEGER NOT NULL REFERENCES users(id),
    account         TEXT    NOT NULL CHECK (length(account) BETWEEN 1 AND 100),
    created_at      TEXT    NOT NULL
);
