CREATE TABLE core_chain_entries_old (
    user_id  INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    chain_id INTEGER NOT NULL REFERENCES core_chains(id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 3),
    pool_id  INTEGER NOT NULL REFERENCES core_pools(id) ON DELETE RESTRICT,
    model    TEXT    CHECK (model IS NULL OR length(model) BETWEEN 1 AND 80),
    PRIMARY KEY (chain_id, position),
    UNIQUE (chain_id, pool_id)
);
INSERT INTO core_chain_entries_old (user_id, chain_id, position, pool_id, model)
    SELECT user_id, chain_id, position, pool_id, model FROM core_chain_entries WHERE position <= 3;
DROP TABLE core_chain_entries;
ALTER TABLE core_chain_entries_old RENAME TO core_chain_entries;
CREATE INDEX core_chain_entries_pool ON core_chain_entries (pool_id);
ALTER TABLE core_chains DROP COLUMN hidden;
ALTER TABLE core_pools DROP COLUMN hidden;
