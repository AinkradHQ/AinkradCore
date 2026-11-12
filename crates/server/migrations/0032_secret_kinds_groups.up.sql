-- Secret kinds, descriptions, one-level groups and use counters (N24). `kind`: text (the
-- default), multiline, file (the sealed value is the file's bytes in base64; `file_name` and
-- `file_mode` say how a runner writes it) or env_bundle (`NAME=value` lines). A group has a
-- description and its own runner list; a member with no runners of its own inherits it.
-- `last_used_at` and `use_count` move at each redemption. Additive only.
CREATE TABLE core_secret_groups (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name        TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 64
                            AND substr(name, 1, 1) GLOB '[a-z]'
                            AND name NOT GLOB '*[^a-z0-9_.-]*'),
    description TEXT    NOT NULL DEFAULT '',
    runners     TEXT    NOT NULL DEFAULT '[]'
                        CHECK (json_valid(runners) AND json_type(runners) = 'array'),
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

ALTER TABLE core_secrets ADD COLUMN kind TEXT NOT NULL DEFAULT 'text'
    CHECK (kind IN ('text', 'multiline', 'file', 'env_bundle'));
ALTER TABLE core_secrets ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE core_secrets ADD COLUMN file_name TEXT;
ALTER TABLE core_secrets ADD COLUMN file_mode INTEGER;
ALTER TABLE core_secrets ADD COLUMN group_id INTEGER REFERENCES core_secret_groups(id);
ALTER TABLE core_secrets ADD COLUMN last_used_at TEXT;
ALTER TABLE core_secrets ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0;
