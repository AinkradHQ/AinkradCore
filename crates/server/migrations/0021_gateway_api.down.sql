-- The wider `provider` check stays: an account of a user-defined provider may exist, and the
-- three-name check cannot be put back without rebuilding the table.
ALTER TABLE core_accounts DROP COLUMN last_test_result;
ALTER TABLE core_accounts DROP COLUMN last_test_at;
ALTER TABLE core_accounts DROP COLUMN session_max_usd_micros;
ALTER TABLE core_accounts DROP COLUMN session_max_tokens;
ALTER TABLE core_provider_defs DROP COLUMN key_prefix;
ALTER TABLE core_provider_defs DROP COLUMN wire;
