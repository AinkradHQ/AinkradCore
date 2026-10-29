-- Requirements and plan-first (E15.10, pain #10, decision #40). A requirement is what the admin
-- asked for: every intake request becomes one, numbered per company (R-12). The projects routing
-- creates for it, and every epic and issue made in them, carry its id (an issue inherits its
-- parent's, else its epic's, else its project's, at insert); planning tools set it explicitly.
--
-- Plan-first: while a requirement is `planning`, `plan_review` or `cancelled`, a run on one of
-- its issues by an agent that does not plan the issue's project (product owner, team lead, CEO,
-- CTO) is not dispatched, and `start` is refused. Its plan is approved through a
-- `plan_approval` approval (or at once under the `product_owner` sprint policy); each approval
-- stores a snapshot of the plan as a version (`requirement_plans`), which later changes are
-- diffed against.
--
-- The owner answers the admin in the requirement's thread: its CEO, then the product owner it
-- was handed to (decision #45); `owner_issue_id` is the issue the owner is woken on.

CREATE TABLE requirements (
    id                   INTEGER PRIMARY KEY,
    company_id           INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    number               INTEGER NOT NULL CHECK (number > 0),
    title                TEXT    NOT NULL CHECK (title <> ''),
    body                 TEXT    NOT NULL DEFAULT '',
    requested_by_user_id INTEGER NOT NULL REFERENCES users(id),
    -- The intake issue it came from; its comment thread is the requirement's thread.
    intake_issue_id      INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    owner_agent_id       INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    owner_issue_id       INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    state                TEXT    NOT NULL DEFAULT 'planning'
                         CHECK (state IN ('planning', 'plan_review', 'in_progress', 'done',
                                          'cancelled')),
    -- The approved plan's version; 0 before the first approval.
    plan_version         INTEGER NOT NULL DEFAULT 0 CHECK (plan_version >= 0),
    created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (company_id, number)
);
CREATE INDEX requirements_intake ON requirements (intake_issue_id);

-- One row per approved plan: its tasks as they were approved.
CREATE TABLE requirement_plans (
    requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
    version        INTEGER NOT NULL CHECK (version > 0),
    -- `[{"id", "key", "title", "epic_id", "points"}]`
    tasks          TEXT    NOT NULL CHECK (json_valid(tasks) AND json_type(tasks) = 'array'),
    approval_id    INTEGER,
    -- `owner` (a person approved) or `product_owner` (the policy let the product owner).
    approved_by    TEXT    NOT NULL CHECK (approved_by IN ('owner', 'product_owner')),
    approved_at    TEXT    NOT NULL,
    PRIMARY KEY (requirement_id, version)
);

ALTER TABLE projects ADD COLUMN requirement_id INTEGER REFERENCES requirements(id)
    ON DELETE SET NULL;
ALTER TABLE epics ADD COLUMN requirement_id INTEGER REFERENCES requirements(id)
    ON DELETE SET NULL;
ALTER TABLE issues ADD COLUMN requirement_id INTEGER REFERENCES requirements(id)
    ON DELETE SET NULL;
CREATE INDEX projects_requirement ON projects (requirement_id);
CREATE INDEX epics_requirement ON epics (requirement_id);
CREATE INDEX issues_requirement ON issues (requirement_id);

-- Approvals gain the `plan_approval` kind and a requirement subject. SQLite cannot alter a
-- CHECK, so the table is rebuilt as in 20261022000002, keeping ids, indexes and trigger.
-- Triggers on other tables that read approvals go while it is rebuilt (20261022000004,
-- 20261022000008), and come back unchanged after.
DROP TRIGGER agents_hired_through_approval;
DROP TRIGGER issues_points_frozen_update;
DROP TRIGGER issues_points_frozen_insert;
CREATE TABLE approvals_new (
    id                      INTEGER PRIMARY KEY,
    user_id                 INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id              INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    kind                    TEXT    NOT NULL CHECK (kind IN ('sprint_commit', 'pr_merge',
                            'budget_overrun', 'hire_agent', 'permission_escalation',
                            'plan_approval')),
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
    requested_by_agent_id, status, decided_by_user_id, reply, payload, expires_at, created_at)
SELECT id, user_id, company_id, kind, issue_id, sprint_id, agent_id, requested_by_agent_id,
    status, decided_by_user_id, reply, payload, expires_at, created_at
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
