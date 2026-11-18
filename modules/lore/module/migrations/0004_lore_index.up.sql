-- Lore R1-04: the index. Link resolution and late resolution look links up by the title they name, and notes
-- by their normalised title; neither had an index. The FTS table (0001) is filled by the save path.
CREATE INDEX lore_links_title ON lore_links (target_title_norm);
CREATE INDEX lore_notes_title ON lore_notes (title_norm) WHERE trashed_at IS NULL;
