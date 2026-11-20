-- A project that never stops for idleness (Core 0.10, E2-4): the Settings page's "Never". The
-- idle_minutes column keeps its 5 to 1440 check, so "never" is its own flag.
ALTER TABLE core_projects ADD COLUMN idle_never INTEGER NOT NULL DEFAULT 0 CHECK (idle_never IN (0, 1));
