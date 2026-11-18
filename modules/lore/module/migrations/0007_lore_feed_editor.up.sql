-- B3-04 review: the Brain must know who last edited a note (`person:…` or `session:…`), so a note an
-- AI session last edited (`loreAiEdit`, `loreAiAppend`, `loreAiCreate`) never grounds an AI proposal.
-- The view gains one column at the end; every column it had stays.
DROP VIEW lore_feed_v1;
CREATE VIEW lore_feed_v1 AS
    SELECT id, project, kind, title, text, rev, updated_at, trashed_at, updated_by FROM lore_notes;
