-- Where a project prefers to run (E11-2): auto, this_mac or home_server. A preference the placement may read; it never blocks a run.
ALTER TABLE core_projects ADD COLUMN runner_pref TEXT NOT NULL DEFAULT 'auto'
    CHECK (runner_pref IN ('auto', 'this_mac', 'home_server'));
