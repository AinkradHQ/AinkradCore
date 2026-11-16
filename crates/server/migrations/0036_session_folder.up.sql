-- The folder an AI session's harness works in, on its runner (E2): the runner reports it once the
-- session has started. Additive only.
ALTER TABLE core_agent_sessions ADD COLUMN folder TEXT;
