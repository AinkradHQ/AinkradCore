ALTER TABLE core_accounts DROP COLUMN plan_limit;
DROP INDEX core_agent_sessions_run;
DROP INDEX core_agent_sessions_failover_of;
ALTER TABLE core_agent_sessions DROP COLUMN skip_pools;
ALTER TABLE core_agent_sessions DROP COLUMN failover_done;
ALTER TABLE core_agent_sessions DROP COLUMN failover_class;
ALTER TABLE core_agent_sessions DROP COLUMN failover_of;
ALTER TABLE core_agent_sessions DROP COLUMN attempt;
ALTER TABLE core_agent_sessions DROP COLUMN run_id;
