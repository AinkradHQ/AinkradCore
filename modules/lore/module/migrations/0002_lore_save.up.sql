-- Lore R1-02: the save path. The ring (`lore_saves`) and `lore_versions` come from 0001; this adds what pruning
-- and listing need. `lore_links.heading` stays NOT NULL DEFAULT '' (R1-01). Nothing here holds a secret.

-- Pruning by kind (auto first), and the newest-first list, both per note.
CREATE INDEX lore_versions_kind ON lore_versions (note, kind, created_at);
-- The ring's 24-hour prune.
CREATE INDEX lore_saves_at ON lore_saves (at);
