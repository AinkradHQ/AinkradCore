DROP INDEX core_agent_sessions_account;
ALTER TABLE core_agent_sessions DROP COLUMN tried_accounts;
ALTER TABLE core_agent_sessions DROP COLUMN waiting;
ALTER TABLE core_agent_sessions DROP COLUMN chain_pos;
ALTER TABLE core_agent_sessions DROP COLUMN chain;
ALTER TABLE core_agent_sessions DROP COLUMN account_id;
