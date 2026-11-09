-- Progress watchdog (E15.7): when a run's runner last saw it progress (a tool call, a file
-- change, a new message, more tokens), apart from the lease heartbeat that only proves its
-- process is alive; and how many files its worktree differs from the base in.
ALTER TABLE runs ADD COLUMN last_progress_at TEXT;
ALTER TABLE runs ADD COLUMN diff_files INTEGER CHECK (diff_files >= 0);
