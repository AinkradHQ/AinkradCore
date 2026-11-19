-- A mirror's explicit state (Core 0.10, E0-4): `fetching` while a fetch runs, `ready` once one
-- succeeded, `failed` with a classified `reason` when it did not.
ALTER TABLE core_project_mirrors ADD COLUMN state TEXT NOT NULL DEFAULT 'ready'
    CHECK (state IN ('fetching', 'ready', 'failed'));
ALTER TABLE core_project_mirrors ADD COLUMN reason TEXT;
ALTER TABLE core_project_mirrors ADD COLUMN started_at TEXT;
UPDATE core_project_mirrors SET state = 'failed' WHERE error IS NOT NULL;
