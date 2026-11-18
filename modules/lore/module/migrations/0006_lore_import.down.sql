DROP TABLE lore_import_items;
DROP TABLE lore_imports;
DROP INDEX lore_notes_import_hash;
DROP INDEX lore_notes_origin;
ALTER TABLE lore_notes DROP COLUMN import_origin;
