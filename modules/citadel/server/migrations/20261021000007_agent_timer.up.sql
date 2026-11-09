-- Scheduler (E2.9): an agent opts in to a heartbeat timer by setting its interval; NULL (the
-- default) leaves it event-driven. `timer_last_fired_at` is when the timer last woke it.
ALTER TABLE agents ADD COLUMN timer_interval_secs INTEGER CHECK (timer_interval_secs > 0);
ALTER TABLE agents ADD COLUMN timer_last_fired_at TEXT;
