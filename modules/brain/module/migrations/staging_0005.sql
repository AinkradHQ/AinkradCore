-- Hot Review queries without a walk through every item's text (SQLite reads a column stored after
-- `text` only by following the text's overflow pages): refused items by their mark, and the
-- id/room/mark of every item for the tidy and the semantic step.
CREATE INDEX items_mark ON items(mark);
CREATE INDEX items_place ON items(item_id, proposal, mark);
