-- A project can be several kinds at once (API 112): `kinds` is the comma-joined list, in order, each
-- one of web, app, infra, other (`other` only alone). `kind` stays and is always the first entry.
ALTER TABLE core_projects ADD COLUMN kinds TEXT NOT NULL DEFAULT 'web';
UPDATE core_projects SET kinds = kind;
