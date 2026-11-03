-- Provider definitions (KAN-429, design 2026-11-02-ai-provider-accounts §4). The three built-in providers live in
-- code (`store::providers::BUILT_IN`) and cannot be edited; a row here is a user definition: data only,
-- validated before it is stored (https base URL, an authentication variable from its harness's own list).
-- `models` is a JSON array of {id, input_per_mtok_micro, output_per_mtok_micro}; `priced_at` says when its list prices were read.
CREATE TABLE core_provider_defs (
    id            TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 32
                      AND substr(id, 1, 1) GLOB '[a-z]' AND id NOT GLOB '*[^a-z0-9-]*'),
    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    harness       TEXT NOT NULL CHECK (harness IN ('claude', 'codex', 'agy')),
    auth_var      TEXT NOT NULL,
    base_url      TEXT NOT NULL CHECK (base_url LIKE 'https://%'),
    usage_parser  TEXT NOT NULL CHECK (usage_parser IN ('anthropic', 'openai', 'google', 'none')),
    delivery      TEXT NOT NULL CHECK (json_valid(delivery) AND json_type(delivery) = 'array'),
    login_methods TEXT NOT NULL CHECK (json_valid(login_methods) AND json_type(login_methods) = 'array'),
    models        TEXT NOT NULL CHECK (json_valid(models) AND json_type(models) = 'array'),
    priced_at     TEXT,
    version       INTEGER NOT NULL CHECK (version >= 1),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- An account is bound, when it is stored, to the base URL its provider had then; an edit of a
-- definition afterwards never moves a stored key to another server.
ALTER TABLE core_accounts ADD COLUMN base_url TEXT NOT NULL DEFAULT '';
