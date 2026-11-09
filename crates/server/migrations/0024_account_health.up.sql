-- Account health (KAN-438 S3, design 2026-11-06 §4.2, §4.3): what the Core remembers to cool an
-- account, count a subscription's failed sign-ins and tell a session's last upstream class.
-- Additive only. `fail_since` is the start of the window the 10-minute error count runs in (the
-- design lists `fail_streak` but not where its window begins). `upstream_class` is the last status
-- class the session's own gateway reported (a trusted channel). `plan_cooled` says the session's
-- plan-limit snapshot has already cooled its account once.
ALTER TABLE core_accounts ADD COLUMN fail_streak INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_accounts ADD COLUMN auth_streak INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_accounts ADD COLUMN backoff_secs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_accounts ADD COLUMN fail_since TEXT;
ALTER TABLE core_accounts ADD COLUMN last_success_at TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN upstream_class TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN plan_cooled INTEGER NOT NULL DEFAULT 0;
