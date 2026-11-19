-- The AI order (E7-1, D-18): one ordered list of accounts per user, held underneath as hidden
-- single-account pools and a hidden chain, so the allocator and failover are untouched. A hidden
-- row never shows in the old pool and chain lists. A chain now holds up to 16 entries (position
-- 0..15); the CHECK is a column constraint, so the table is rebuilt (nothing references it).
ALTER TABLE core_pools ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0 CHECK (hidden IN (0, 1));
ALTER TABLE core_chains ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0 CHECK (hidden IN (0, 1));

CREATE TABLE core_chain_entries_new (
    user_id  INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    chain_id INTEGER NOT NULL REFERENCES core_chains(id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 15),
    pool_id  INTEGER NOT NULL REFERENCES core_pools(id) ON DELETE RESTRICT,
    model    TEXT    CHECK (model IS NULL OR length(model) BETWEEN 1 AND 80),
    PRIMARY KEY (chain_id, position),
    UNIQUE (chain_id, pool_id)
);
INSERT INTO core_chain_entries_new (user_id, chain_id, position, pool_id, model)
    SELECT user_id, chain_id, position, pool_id, model FROM core_chain_entries;
DROP TABLE core_chain_entries;
ALTER TABLE core_chain_entries_new RENAME TO core_chain_entries;
CREATE INDEX core_chain_entries_pool ON core_chain_entries (pool_id);
