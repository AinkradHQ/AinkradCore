DROP VIEW lore_feed_v1;
CREATE VIEW lore_feed_v1 AS
    SELECT id, project, kind, title, text, rev, updated_at, trashed_at FROM lore_notes;
