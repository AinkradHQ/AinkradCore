ALTER TABLE core_agent_sessions DROP COLUMN plan_cooled;
ALTER TABLE core_agent_sessions DROP COLUMN upstream_class;
ALTER TABLE core_accounts DROP COLUMN last_success_at;
ALTER TABLE core_accounts DROP COLUMN fail_since;
ALTER TABLE core_accounts DROP COLUMN backoff_secs;
ALTER TABLE core_accounts DROP COLUMN auth_streak;
ALTER TABLE core_accounts DROP COLUMN fail_streak;
