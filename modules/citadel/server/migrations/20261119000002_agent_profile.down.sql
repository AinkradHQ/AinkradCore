-- Agents without their profile.
ALTER TABLE agents DROP COLUMN guidelines;
ALTER TABLE agents DROP COLUMN instructions;
ALTER TABLE agents DROP COLUMN sandbox;
ALTER TABLE agents DROP COLUMN effort;
ALTER TABLE agents DROP COLUMN description;
