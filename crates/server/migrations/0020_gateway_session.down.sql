DROP TABLE core_account_auth_signals;
ALTER TABLE core_agent_sessions DROP COLUMN gw_prices;
ALTER TABLE core_agent_sessions DROP COLUMN gw_ceiling_usd;
ALTER TABLE core_agent_sessions DROP COLUMN gw_ceiling_tokens;
ALTER TABLE core_agent_sessions DROP COLUMN gw_epoch;
ALTER TABLE core_agent_sessions DROP COLUMN gw_stopped_at;
ALTER TABLE core_agent_sessions DROP COLUMN gw_stop;
ALTER TABLE core_agent_sessions DROP COLUMN gw_seq;
ALTER TABLE core_agent_sessions DROP COLUMN gateway_account_id;
