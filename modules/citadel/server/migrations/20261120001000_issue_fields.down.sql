-- Chores and spikes become tasks; the kind list and the columns go.
UPDATE issues SET kind = 'task' WHERE kind IN ('chore', 'spike');
PRAGMA writable_schema = ON;
UPDATE sqlite_schema SET sql = replace(sql,
    'kind IN (''story'', ''task'', ''bug'', ''chore'', ''spike'', ''subtask'')',
    'kind IN (''story'', ''task'', ''bug'', ''subtask'')')
WHERE type = 'table' AND name = 'issues';
PRAGMA writable_schema = RESET;
CREATE TABLE issue_kind_schema_bump (x);
DROP TABLE issue_kind_schema_bump;
ALTER TABLE issues DROP COLUMN criteria;
ALTER TABLE issues DROP COLUMN priority_level;
