DROP TRIGGER issues_updated_at;
ALTER TABLE issues DROP COLUMN updated_at;
DROP TABLE linear_issues;
DROP TABLE project_linear;
