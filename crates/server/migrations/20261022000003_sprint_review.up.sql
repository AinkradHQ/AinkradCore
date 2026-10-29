-- Sprint review and retro (E5.5). Closing a sprint stores its review summary (JSON:
-- committed vs completed, carried issues, velocity delta, blockers and escalations from the
-- audit log) on the sprint. Retro items are knowledge entries proposed from a sprint; the link
-- says which (E8 accepts or rejects them).

ALTER TABLE sprints ADD COLUMN review TEXT CHECK (review IS NULL OR json_valid(review));

CREATE TABLE sprint_retro_items (
    entry_id  INTEGER PRIMARY KEY REFERENCES knowledge_entries(id) ON DELETE CASCADE,
    sprint_id INTEGER NOT NULL REFERENCES sprints(id) ON DELETE CASCADE
);
CREATE INDEX sprint_retro_items_sprint ON sprint_retro_items (sprint_id);

CREATE TRIGGER sprint_retro_items_same_project BEFORE INSERT ON sprint_retro_items
BEGIN
    SELECT RAISE(ABORT, 'sprint belongs to another project')
    WHERE (SELECT project_id FROM sprints WHERE id = NEW.sprint_id)
       <> (SELECT project_id FROM knowledge_entries WHERE id = NEW.entry_id);
END;
