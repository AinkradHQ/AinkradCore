-- Stage timings (E15.6): when a run's wake was due, its harness came up and the model first
-- answered. With `claimed_at`, `started_at` (the workspace is ready) and `ended_at`, a run's
-- start is wake → claim → workspace → harness → first token → end.
ALTER TABLE runs ADD COLUMN woken_at TEXT;
ALTER TABLE runs ADD COLUMN harness_started_at TEXT;
ALTER TABLE runs ADD COLUMN first_token_at TEXT;
