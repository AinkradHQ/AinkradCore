-- The hire gate (E6.4): a new agent starts `pending_approval` and becomes active only through
-- an approved `hire_agent` approval about it (dispatch already runs active agents only). The
-- one agent that starts active is a company's first CEO, bootstrapped by the admin.
CREATE TRIGGER agents_hired_through_approval BEFORE UPDATE OF status ON agents
WHEN OLD.status = 'pending_approval' AND NEW.status = 'active' AND NOT EXISTS (
    SELECT 1 FROM approvals WHERE kind = 'hire_agent' AND agent_id = NEW.id
    AND status = 'approved')
BEGIN
    SELECT RAISE(ABORT, 'an agent is hired only through an approved hire_agent approval');
END;
