-- Chain presets (parity API B2, item 3): a named, coloured chain of (harness, model, account)
-- entries a company's agents share. An agent with a preset uses its entries in place of its own
-- fallbacks (`agent_fallbacks` stay stored and come back when the preset is cleared); an agent
-- with neither a preset nor fallbacks of its own uses the company's default preset, if any.
CREATE TABLE chain_presets (
    id          INTEGER PRIMARY KEY,
    company_id  INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL CHECK (name <> ''),
    color       TEXT    CHECK (color IS NULL OR color GLOB '#[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]'),
    description TEXT    NOT NULL DEFAULT '',
    is_default  INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (company_id, name)
);
CREATE UNIQUE INDEX chain_presets_default ON chain_presets (company_id) WHERE is_default = 1;

-- `account_id`: the entry works on that account only (stored and shown; dispatch does not yet
-- honour the pin).
CREATE TABLE chain_preset_entries (
    preset_id  INTEGER NOT NULL REFERENCES chain_presets(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL CHECK (position >= 1),
    harness    TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model      TEXT    NOT NULL CHECK (model <> ''),
    account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
    PRIMARY KEY (preset_id, position)
);

ALTER TABLE agents ADD COLUMN chain_preset_id INTEGER REFERENCES chain_presets(id) ON DELETE SET NULL;
CREATE INDEX agents_chain_preset ON agents (chain_preset_id);
