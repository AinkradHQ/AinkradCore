-- Fallback chains (KAN-437 family, S5; design 2026-11-06-core-account-scheduler §4.1, §4.2, §4.5). A chain
-- is an ORDERED list of (pool, model) entries; the entry's harness is its pool's provider's, read when the
-- chain is loaded (a stored copy could go stale), so it is not a column. `position` is 0..3 in fallback order.
-- A pool a chain names is never deleted (RESTRICT; the store says which chain). Deleting a chain takes its
-- entries and bindings with it. At most one default chain per user.
CREATE TABLE core_chains (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name       TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

CREATE UNIQUE INDEX core_chains_one_default ON core_chains (user_id) WHERE is_default = 1;

CREATE TABLE core_chain_entries (
    user_id  INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    chain_id INTEGER NOT NULL REFERENCES core_chains(id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 3),
    pool_id  INTEGER NOT NULL REFERENCES core_pools(id) ON DELETE RESTRICT,
    model    TEXT    CHECK (model IS NULL OR length(model) BETWEEN 1 AND 80),
    PRIMARY KEY (chain_id, position),
    -- A pool twice in one chain would let a run revisit its accounts.
    UNIQUE (chain_id, pool_id)
);

CREATE INDEX core_chain_entries_pool ON core_chain_entries (pool_id);

-- An agent (an opaque id, as in `core_pool_bindings`) and the chain its sessions walk. One binding per
-- user and agent: one user never replaces another's.
CREATE TABLE core_chain_bindings (
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    agent      TEXT    NOT NULL CHECK (length(agent) BETWEEN 1 AND 64),
    chain_id   INTEGER NOT NULL REFERENCES core_chains(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL,
    PRIMARY KEY (user_id, agent)
);

CREATE INDEX core_chain_bindings_chain ON core_chain_bindings (chain_id);

-- A session's chain: `chain_id` is the chain it was given (no foreign key: the chain may be deleted
-- once the run is over) and `agent` the opaque agent id from the create request. The snapshot of the
-- resolved entries is S4's `chain` column (0025: JSON array of {pool, provider, harness, model}), so
-- an edit never moves a running run.
ALTER TABLE core_agent_sessions ADD COLUMN agent TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN chain_id INTEGER;
