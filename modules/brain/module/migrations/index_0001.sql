-- A room's search index (plan §3.1, E7-1): derived from `canon.db`, rebuilt when it is missing or
-- behind, never synced or backed up. Encrypted with the brain key like every other file.
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE VIRTUAL TABLE fts USING fts5(
    item_id UNINDEXED, source_kind UNINDEXED, started_at UNINDEXED, title, text,
    tokenize = 'unicode61 remove_diacritics 2'
);
