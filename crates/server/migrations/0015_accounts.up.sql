-- AI provider accounts, owned by the Core (KAN-428, design 2026-11-02-ai-provider-accounts §4). An account is
-- one API key of one provider. The key itself lives only in the secrets broker (`secret_name` names it,
-- `acct.<provider>.<id>`); this row holds no value, and `masked_tail` (the last four characters, cut at
-- write time) is the only trace of it outside the broker. Which runners may be leased the key is the
-- broker secret's own scope (`core_secrets.runners`), never copied here. There is no company column:
-- accounts are global, and Citadel only consumes them.
-- AUTOINCREMENT: an id (and so a `acct.<provider>.<id>` secret name) is never reused after a delete.
-- `cap` is the number of sessions that may hold the account at once; 0 turns the cap off (KAN-437 enforces it).
CREATE TABLE core_accounts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    provider     TEXT    NOT NULL CHECK (provider IN ('anthropic', 'openai', 'google')),
    label        TEXT    NOT NULL UNIQUE CHECK (length(label) BETWEEN 1 AND 64),
    secret_name  TEXT    NOT NULL UNIQUE,
    masked_tail  TEXT    NOT NULL CHECK (length(masked_tail) <= 4),
    state        TEXT    NOT NULL DEFAULT 'active'
                         CHECK (state IN ('active', 'cooling', 'limited', 'unhealthy', 'disabled')),
    state_reason TEXT,
    state_until  TEXT    CHECK (state_until IS NULL OR julianday(state_until) IS NOT NULL),
    cap          INTEGER NOT NULL DEFAULT 4 CHECK (cap BETWEEN 0 AND 64),
    owner        TEXT    NOT NULL REFERENCES core_devices(id),
    last_used_at TEXT,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);
