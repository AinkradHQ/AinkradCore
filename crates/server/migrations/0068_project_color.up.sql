-- A project's colour (API 110): one of the app's accent names, checked by the Core (`COLORS`);
-- none until one is picked.
ALTER TABLE core_projects ADD COLUMN color TEXT;
