-- The memory search (Brain v2, B2-01): the facts in force, one row each. Derived like `fts`: rebuilt
-- from `canon.db` when behind, never synced or backed up.
CREATE VIRTUAL TABLE rec_fts USING fts5(
    record UNINDEXED, type UNINDEXED, body, tags,
    tokenize = 'unicode61 remove_diacritics 2'
);
