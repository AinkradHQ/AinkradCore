-- Per-project fetch interval and default run environment (Core 0.10, E11-3). The interval is
-- minutes between automatic fetches: 10, 15, 60, or 0 for only when asked. The default
-- environment is one of the project's run environments, checked when it is set.
ALTER TABLE core_projects ADD COLUMN fetch_interval_minutes INTEGER NOT NULL DEFAULT 15
    CHECK (fetch_interval_minutes IN (0, 10, 15, 60));
ALTER TABLE core_projects ADD COLUMN default_environment TEXT;
