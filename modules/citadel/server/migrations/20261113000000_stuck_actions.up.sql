-- The stuck list's actions (the Mac plugin's "Why stuck" screen).
--
-- A wake the admin pinned to one runner ("retry on this runner"): only that runner is given it
-- (`dispatch_next`), and it is stuck while that runner cannot take it. A plain id, as
-- `issues.checkout_run_id`: a runner since removed leaves the wake stuck, never served elsewhere.
ALTER TABLE wake_requests ADD COLUMN runner_id INTEGER;
-- An issue the admin bumped: at the top of its backlog, and its wakes dispatched first.
ALTER TABLE issues ADD COLUMN priority INTEGER NOT NULL DEFAULT 0 CHECK (priority IN (0, 1));
