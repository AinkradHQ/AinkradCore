DROP TRIGGER issues_history_update;
DROP TRIGGER issues_history_insert;
DROP TABLE issue_state_history;
ALTER TABLE team_memberships DROP COLUMN capacity;
ALTER TABLE sprints DROP COLUMN completed_points;
ALTER TABLE sprints DROP COLUMN committed_points;
