-- What a request is filed with and what the admin does to a requirement (API minor 18): the
-- project it is for (a hint to the CEO, cleared when the project goes), a priority level,
-- acceptance criteria (a JSON array of objects with text and done) and when it was paused. A
-- paused requirement holds its issues like an unapproved plan: no wake for them is dispatched.
ALTER TABLE requirements ADD COLUMN project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE requirements ADD COLUMN priority_level TEXT NOT NULL DEFAULT 'none'
    CHECK (priority_level IN ('none', 'low', 'medium', 'high', 'urgent'));
ALTER TABLE requirements ADD COLUMN criteria TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(criteria));
ALTER TABLE requirements ADD COLUMN paused_at TEXT;
