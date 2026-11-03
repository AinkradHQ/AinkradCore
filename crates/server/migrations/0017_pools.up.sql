-- Account pools and bindings (KAN-431, design 2026-11-02-ai-provider-accounts §4, §6). A pool groups accounts of ONE
-- provider (fallback never crosses providers, decision 7); balancing and failover happen inside it. Each
-- provider has at most one default pool, which serves an agent that is bound to none. A binding names an
-- agent (an opaque id, at most 64 characters, owned by whoever runs agents) and the pool it draws from.
-- `position` orders the members: the order a pool falls back in when nothing else separates two accounts.
CREATE TABLE core_pools (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name       TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
    provider   TEXT    NOT NULL CHECK (provider IN ('anthropic', 'openai', 'google')),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

CREATE UNIQUE INDEX core_pools_one_default ON core_pools (provider) WHERE is_default = 1;

CREATE TABLE core_pool_members (
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    pool_id    INTEGER NOT NULL REFERENCES core_pools(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES core_accounts(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (pool_id, account_id)
);

CREATE INDEX core_pool_members_account ON core_pool_members (account_id);

CREATE TABLE core_pool_bindings (
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    agent      TEXT    NOT NULL CHECK (length(agent) BETWEEN 1 AND 64),
    provider   TEXT    NOT NULL CHECK (provider IN ('anthropic', 'openai', 'google')),
    pool_id    INTEGER NOT NULL REFERENCES core_pools(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL,
    PRIMARY KEY (agent, provider)
);
