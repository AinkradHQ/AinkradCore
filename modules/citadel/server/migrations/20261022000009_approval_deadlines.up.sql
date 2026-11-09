-- Approval deadlines per kind (E7.1): a new approval expires `deadline_secs` after it opens,
-- or never when NULL. Set with `ainkrad-core-server approval deadline`. A permission escalation
-- carries its runner's own timeout instead; 900 s (the runner's default, 15 min) is only the
-- fallback for a runner too old to send one. The other kinds keep waiting until decided, as
-- before, until someone sets a deadline.
CREATE TABLE approval_deadlines (
    kind          TEXT    PRIMARY KEY CHECK (kind IN ('sprint_commit', 'pr_merge',
                  'budget_overrun', 'hire_agent', 'permission_escalation')),
    deadline_secs INTEGER CHECK (deadline_secs > 0)
);
INSERT INTO approval_deadlines (kind, deadline_secs) VALUES
    ('sprint_commit', NULL),
    ('pr_merge', NULL),
    ('budget_overrun', NULL),
    ('hire_agent', NULL),
    ('permission_escalation', 900);
