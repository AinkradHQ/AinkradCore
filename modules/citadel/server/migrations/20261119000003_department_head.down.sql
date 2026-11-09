-- Departments without an about text or a head.
ALTER TABLE departments DROP COLUMN head_agent_id;
ALTER TABLE departments DROP COLUMN about;
