-- The running turn's cost so far (E6): priced from the turn's latest `usage_so_far` entry with the
-- price book, set to 0 when a message starts a turn and cleared when it ends. Additive only.
ALTER TABLE core_agent_sessions ADD COLUMN turn_cost_micros INTEGER;
ALTER TABLE core_agent_sessions ADD COLUMN turn_cost_approx INTEGER NOT NULL DEFAULT 0;
