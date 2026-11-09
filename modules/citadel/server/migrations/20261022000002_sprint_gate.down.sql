-- Back to approvals without deadlines. An expired approval becomes a rejection by the admin
-- (user 1), keeping its reason as the reply: the old schema has no undecided outcome.
CREATE TABLE approvals_old (
    id                      INTEGER PRIMARY KEY,
    user_id                 INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id              INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    kind                    TEXT    NOT NULL CHECK (kind IN ('sprint_commit', 'pr_merge',
                            'budget_overrun', 'hire_agent', 'permission_escalation')),
    issue_id                INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    sprint_id               INTEGER REFERENCES sprints(id) ON DELETE SET NULL,
    agent_id                INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    requested_by_agent_id   INTEGER NOT NULL REFERENCES agents(id),
    status                  TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'rejected')),
    decided_by_user_id      INTEGER REFERENCES users(id),
    reply                   TEXT,
    payload                 TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((status = 'pending') = (decided_by_user_id IS NULL))
);
INSERT INTO approvals_old (id, user_id, company_id, kind, issue_id, sprint_id, agent_id,
    requested_by_agent_id, status, decided_by_user_id, reply, payload, created_at)
SELECT id, user_id, company_id, kind, issue_id, sprint_id, agent_id, requested_by_agent_id,
    iif(status = 'expired', 'rejected', status),
    iif(status = 'expired', 1, decided_by_user_id), reply, payload, created_at
FROM approvals;
DROP TABLE approvals;
ALTER TABLE approvals_old RENAME TO approvals;

CREATE INDEX approvals_pending ON approvals (company_id) WHERE status = 'pending';
CREATE INDEX approvals_requested_by ON approvals (requested_by_agent_id);
CREATE INDEX approvals_issue ON approvals (issue_id);
CREATE INDEX approvals_sprint ON approvals (sprint_id);
CREATE INDEX approvals_agent ON approvals (agent_id);

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

ALTER TABLE projects DROP COLUMN spec;
