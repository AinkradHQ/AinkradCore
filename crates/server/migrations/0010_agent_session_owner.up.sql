-- A session a module created and drives on its own (E2-13, S7): the run engine starts and stops
-- the sessions of its runs without a client in hand. NULL for a session a client created; the
-- module service refuses a session that does not name the module (`agents::instruct_module`).
ALTER TABLE core_agent_sessions ADD COLUMN owner_module TEXT
    CHECK (owner_module IS NULL OR length(owner_module) BETWEEN 1 AND 32);
