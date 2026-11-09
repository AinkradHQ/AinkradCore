DROP INDEX agents_chain_preset;
ALTER TABLE agents DROP COLUMN chain_preset_id;
DROP TABLE chain_preset_entries;
DROP INDEX chain_presets_default;
DROP TABLE chain_presets;
