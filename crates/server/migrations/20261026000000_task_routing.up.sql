-- Per-task model routing (E15.5): a task's tier picks the model it starts on. An agent's own
-- (harness, model) is its standard tier; `agent_tiers` holds its small and large ones.
CREATE TABLE agent_tiers (
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tier     TEXT    NOT NULL CHECK (tier IN ('small', 'large')),
    harness  TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model    TEXT    NOT NULL CHECK (model <> ''),
    PRIMARY KEY (agent_id, tier)
);

-- A project's routing rules: an issue with this label or kind runs on this tier. A project
-- with none uses the built-in defaults (`label:chore` and `label:docs` are small).
CREATE TABLE tier_rules (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule       TEXT    NOT NULL CHECK (rule GLOB 'label:?*' OR rule GLOB 'kind:?*'),
    tier       TEXT    NOT NULL CHECK (tier IN ('small', 'standard', 'large')),
    PRIMARY KEY (project_id, rule)
);

-- The tier a run started on, and its first turn's input tokens (its context size).
ALTER TABLE runs ADD COLUMN tier TEXT CHECK (tier IN ('small', 'standard', 'large'));
ALTER TABLE runs ADD COLUMN context_tokens INTEGER CHECK (context_tokens >= 0);
