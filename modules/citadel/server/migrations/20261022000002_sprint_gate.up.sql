-- The sprint commit gate (E5.4) and approval expiry. A project gets its spec, the text its
-- product owner and team lead plan from. Approvals get a deadline (`expires_at`) and the
-- `expired` status: an approval nobody decided in time, or whose run has ended, is closed
-- with the reason in `reply` and no decider.
--
-- SQLite cannot alter a CHECK, so `approvals` is rebuilt, keeping its ids, indexes and
-- trigger.

ALTER TABLE projects ADD COLUMN spec TEXT NOT NULL DEFAULT '';

CREATE TABLE approvals_new (
    id                      INTEGER PRIMARY KEY,
    user_id                 INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id              INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    kind                    TEXT    NOT NULL CHECK (kind IN ('sprint_commit', 'pr_merge',
                            'budget_overrun', 'hire_agent', 'permission_escalation')),
    -- Subjects; an approval outlives them.
    issue_id                INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    sprint_id               INTEGER REFERENCES sprints(id) ON DELETE SET NULL,
    agent_id                INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    -- The requester cannot be deleted while it has approvals (terminate it instead).
    requested_by_agent_id   INTEGER NOT NULL REFERENCES agents(id),
    status                  TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    decided_by_user_id      INTEGER REFERENCES users(id),
    reply                   TEXT,
    payload                 TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),
    -- When a pending approval expires; NULL when it waits for as long as it takes.
    expires_at              TEXT,
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- A human decides approve / reject; nobody decides pending or expired.
    CHECK ((status IN ('approved', 'rejected')) = (decided_by_user_id IS NOT NULL))
);
INSERT INTO approvals_new (id, user_id, company_id, kind, issue_id, sprint_id, agent_id,
    requested_by_agent_id, status, decided_by_user_id, reply, payload, created_at)
SELECT id, user_id, company_id, kind, issue_id, sprint_id, agent_id, requested_by_agent_id,
    status, decided_by_user_id, reply, payload, created_at
FROM approvals;
DROP TABLE approvals;
ALTER TABLE approvals_new RENAME TO approvals;

CREATE INDEX approvals_pending ON approvals (company_id) WHERE status = 'pending';
CREATE INDEX approvals_requested_by ON approvals (requested_by_agent_id);
CREATE INDEX approvals_issue ON approvals (issue_id);
CREATE INDEX approvals_sprint ON approvals (sprint_id);
CREATE INDEX approvals_agent ON approvals (agent_id);
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
END;
