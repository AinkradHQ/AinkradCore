-- The issue's branch, named once from its project profile's branch_pattern (or
-- `citadel/<KEY>-<n>`) when its first run is dispatched, then kept for the issue's life: every
-- repo it touches and every later run use the same name.
ALTER TABLE issues ADD COLUMN branch TEXT;
