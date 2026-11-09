DROP TABLE issue_allow_rules;
DROP TABLE run_controls;
ALTER TABLE runners DROP COLUMN wake_requested_at;
ALTER TABLE agents DROP COLUMN paused_at;
