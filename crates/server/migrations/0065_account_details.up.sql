-- Account details (0.10.4). Additive only.
-- The model the harness says it runs (Claude's `system/init`, Codex's `thread/start` answer), from the
-- runner's `session_started` entry: the real one when the session left the harness its default
-- (`model` NULL). Harness output, so only a label: the meter records it on a plan's ledger rows.
ALTER TABLE core_agent_sessions ADD COLUMN harness_model TEXT
    CHECK (harness_model IS NULL OR length(harness_model) BETWEEN 1 AND 80);
-- The last test or check of an account: how long it took to answer and the runner that ran it.
ALTER TABLE core_accounts ADD COLUMN last_test_ms INTEGER;
ALTER TABLE core_accounts ADD COLUMN last_test_runner TEXT;
