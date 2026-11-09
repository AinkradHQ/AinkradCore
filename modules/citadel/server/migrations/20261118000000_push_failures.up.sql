-- Push failures (#103). A run whose branch push the remote refused for good (a token without
-- the `workflow` scope, a protected branch, no permission) holds its issue's PR request:
-- `push_held` is the refusal. A held request is not re-armed by later runs; the forge poller
-- opens it quietly once the branch is on the forge (a human pushed it, or a later run's push
-- went through, which clears the hold).
ALTER TABLE issue_prs ADD COLUMN push_held TEXT;

-- Approvals gain the `workflow_push` kind: a push refused for changing workflow files waits for
-- a human to push the branch with credentials that may. SQLite cannot alter a CHECK, so the
-- table is rebuilt as in 20261102000000, keeping ids, indexes and triggers.
-- Dropping approvals would null `issue_allow_rules.approval_id` (ON DELETE SET NULL, with
-- foreign keys on): kept aside and put back.
CREATE TEMP TABLE kept_allow_approvals AS
    SELECT id, approval_id FROM issue_allow_rules WHERE approval_id IS NOT NULL;
DROP TRIGGER agents_hired_through_approval;
DROP TRIGGER issues_points_frozen_update;
DROP TRIGGER issues_points_frozen_insert;
CREATE TABLE approvals_new (
    id                      INTEGER PRIMARY KEY,
    user_id                 INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id              INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    kind                    TEXT    NOT NULL CHECK (kind IN ('sprint_commit', 'pr_merge',
                            'budget_overrun', 'hire_agent', 'permission_escalation',
                            'plan_approval', 'workflow_push')),
    issue_id                INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    sprint_id               INTEGER REFERENCES sprints(id) ON DELETE SET NULL,
    agent_id                INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    requirement_id          INTEGER REFERENCES requirements(id) ON DELETE SET NULL,
    requested_by_agent_id   INTEGER NOT NULL REFERENCES agents(id),
    status                  TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    decided_by_user_id      INTEGER REFERENCES users(id),
    reply                   TEXT,
    payload                 TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),
    expires_at              TEXT,
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((status IN ('approved', 'rejected')) = (decided_by_user_id IS NOT NULL))
);
INSERT INTO approvals_new (id, user_id, company_id, kind, issue_id, sprint_id, agent_id,
    requirement_id, requested_by_agent_id, status, decided_by_user_id, reply, payload,
    expires_at, created_at)
SELECT id, user_id, company_id, kind, issue_id, sprint_id, agent_id, requirement_id,
    requested_by_agent_id, status, decided_by_user_id, reply, payload, expires_at, created_at
FROM approvals;
DROP TABLE approvals;
ALTER TABLE approvals_new RENAME TO approvals;
CREATE TRIGGER agents_hired_through_approval BEFORE UPDATE OF status ON agents
WHEN OLD.status = 'pending_approval' AND NEW.status = 'active' AND NOT EXISTS (
    SELECT 1 FROM approvals WHERE kind = 'hire_agent' AND agent_id = NEW.id
    AND status = 'approved')
BEGIN
    SELECT RAISE(ABORT, 'an agent is hired only through an approved hire_agent approval');
END;
CREATE TRIGGER issues_points_frozen_update BEFORE UPDATE OF points ON issues
WHEN NEW.points IS NOT OLD.points AND EXISTS (SELECT 1 FROM approvals
    WHERE sprint_id = NEW.sprint_id AND kind = 'sprint_commit' AND status = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'estimates are frozen while the sprint commit awaits approval');
END;
CREATE TRIGGER issues_points_frozen_insert BEFORE INSERT ON issues
WHEN NEW.points IS NOT NULL AND EXISTS (SELECT 1 FROM approvals
    WHERE sprint_id = NEW.sprint_id AND kind = 'sprint_commit' AND status = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'estimates are frozen while the sprint commit awaits approval');
END;


CREATE INDEX approvals_pending ON approvals (company_id) WHERE status = 'pending';
CREATE INDEX approvals_requested_by ON approvals (requested_by_agent_id);
CREATE INDEX approvals_issue ON approvals (issue_id);
CREATE INDEX approvals_sprint ON approvals (sprint_id);
CREATE INDEX approvals_agent ON approvals (agent_id);
CREATE INDEX approvals_requirement ON approvals (requirement_id);
CREATE INDEX approvals_expiring ON approvals (expires_at) WHERE status = 'pending';

CREATE TRIGGER approvals_same_company BEFORE INSERT ON approvals
BEGIN
    SELECT RAISE(ABORT, 'requester belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.requested_by_agent_id)
       <> NEW.company_id;
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.agent_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'issue belongs to another company')
    WHERE (SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id
           WHERE i.id = NEW.issue_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'sprint belongs to another company')
    WHERE (SELECT p.company_id FROM sprints s JOIN projects p ON p.id = s.project_id
           WHERE s.id = NEW.sprint_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'requirement belongs to another company')
    WHERE (SELECT company_id FROM requirements WHERE id = NEW.requirement_id) <> NEW.company_id;
END;

UPDATE issue_allow_rules SET approval_id = (SELECT k.approval_id FROM kept_allow_approvals k
    WHERE k.id = issue_allow_rules.id) WHERE id IN (SELECT id FROM kept_allow_approvals);
DROP TABLE kept_allow_approvals;
