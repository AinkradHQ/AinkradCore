-- Failover execution (KAN-438 part B, S6; design 2026-11-06-core-account-scheduler §4.2, §8). Additive only.
-- A failover is a NEW session row (an attempt) of the same run: `run_id` is the first attempt's id (NULL on the
-- first attempt itself: read it as coalesce(run_id, id)), `attempt` counts from 0, and `failover_of` names the
-- attempt this one replaces. The unique partial index is the idempotency: one attempt has at most one successor,
-- whichever supervisor, restart or retry makes it. `failover_class` is the move decided for an attempt, written
-- BEFORE any stop is sent (the runner reports that stop as a plain cancel). `failover_done` is 1 once the attempt's
-- failover is settled (a successor exists, the run ended, or a person cancelled the run): a restart finds the
-- ended attempts with 0 and finishes them exactly once. `skip_pools` is the JSON list of pool ids a budget stop
-- has taken out of this run's chain.
ALTER TABLE core_agent_sessions ADD COLUMN run_id TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_agent_sessions ADD COLUMN failover_of TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN failover_class TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN failover_done INTEGER NOT NULL DEFAULT 0;
-- `gw_stop_budget` is the budget a stop names, as `<kind>:<subject>` (`pool:12`, `account:5`): written by the Core
-- with `gw_stop` when an account or pool budget ran out, NULL for a stop that is a ceiling or a session limit.
ALTER TABLE core_agent_sessions ADD COLUMN gw_stop_budget TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN skip_pools TEXT NOT NULL DEFAULT '[]';
CREATE UNIQUE INDEX core_agent_sessions_failover_of ON core_agent_sessions (failover_of)
    WHERE failover_of IS NOT NULL;
CREATE INDEX core_agent_sessions_run ON core_agent_sessions (run_id) WHERE run_id IS NOT NULL;

-- Every session that is over already is settled: only an attempt that ends from now on may move a run.
UPDATE core_agent_sessions SET failover_done = 1 WHERE state IN ('ended', 'lost');

-- The latest plan-limit snapshot of a subscription (JSON `{"at": unix, "plan": {...}}`), kept so the
-- allocator can treat a `rejected` plan as cooling when no window says when it resets. Harness output,
-- so it only ever cools (it never disables).
ALTER TABLE core_accounts ADD COLUMN plan_limit TEXT;
