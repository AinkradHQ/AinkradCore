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
UPDATE approval_deadlines SET deadline_secs = (SELECT nullif(CAST(s.value AS INTEGER), 0)
    FROM settings s WHERE s.key = 'approval.deadline.' || approval_deadlines.kind
    AND s.scope_kind = 'server')
WHERE EXISTS (SELECT 1 FROM settings s WHERE s.key = 'approval.deadline.' ||
    approval_deadlines.kind AND s.scope_kind = 'server');
DROP TABLE settings;
