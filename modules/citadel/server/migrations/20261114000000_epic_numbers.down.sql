DROP TRIGGER epics_number;
DROP INDEX epics_number;
ALTER TABLE epics DROP COLUMN number;
ALTER TABLE projects DROP COLUMN next_epic_number;
