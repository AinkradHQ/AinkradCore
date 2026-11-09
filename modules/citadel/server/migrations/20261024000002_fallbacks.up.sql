-- Model fallback chains (E15.3): an agent's ordered (harness, model) entries after its own.
-- A run starts on the first entry with an account it may use (E15.1) and moves to the next
-- when its model is unavailable, rate-limited or out of quota; the run records the model it
-- worked with (`model_used`) and why it is not its agent's first choice (`fallback_reason`,
-- every reason in order).
CREATE TABLE agent_fallbacks (
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 1),
    harness  TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model    TEXT    NOT NULL CHECK (model <> ''),
    PRIMARY KEY (agent_id, position)
);

ALTER TABLE runs ADD COLUMN model_used TEXT;
ALTER TABLE runs ADD COLUMN fallback_reason TEXT CHECK (fallback_reason <> '');
