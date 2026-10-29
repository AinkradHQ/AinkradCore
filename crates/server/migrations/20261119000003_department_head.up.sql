-- A department's own words and its head (API minor 17). The head is an agent of the company; it
-- is unset when that agent is deleted.
ALTER TABLE departments ADD COLUMN about TEXT NOT NULL DEFAULT '';
ALTER TABLE departments ADD COLUMN head_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL;
