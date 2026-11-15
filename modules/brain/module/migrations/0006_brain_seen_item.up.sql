-- Which collected item (its stable id) a seen hash came from, so an item imported again with new
-- text is updated in its room instead of stored a second time. Ids only, never text.
ALTER TABLE brain_seen ADD COLUMN item_id TEXT;
CREATE INDEX brain_seen_item ON brain_seen(item_id);
