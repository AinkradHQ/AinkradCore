-- The account allocator (KAN-437 S4, design 2026-11-06 §4.2, §5). Additive only.
-- `account_id` is the allocated account whatever its delivery (an API key's equals
-- `gateway_account_id`; a subscription has no gateway id). `chain` is the JSON snapshot of the
-- entries the session draws from ([{pool, provider, harness, model}]) and `chain_pos` the entry it
-- sits on; both are NULL for a session that names its account itself, and S5 (chains) writes them at
-- create. `waiting` is `{"until", "why"}` while the allocator has nothing to give yet. `tried_accounts`
-- is the JSON list of accounts a launch refused after the pick (a re-pick, at most two).
ALTER TABLE core_agent_sessions ADD COLUMN account_id INTEGER;
ALTER TABLE core_agent_sessions ADD COLUMN chain TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN chain_pos INTEGER;
ALTER TABLE core_agent_sessions ADD COLUMN waiting TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN tried_accounts TEXT NOT NULL DEFAULT '[]';
-- 1 once the Core has sent `agent.start` for the row (or may have): the pick is final from then on.
ALTER TABLE core_agent_sessions ADD COLUMN start_sent INTEGER NOT NULL DEFAULT 0;
CREATE INDEX core_agent_sessions_account ON core_agent_sessions (account_id, state);

-- Every session under an account name (over ones too: a wake brings them back) is bound to that
-- account, as a new one is bound at create.
UPDATE core_agent_sessions SET account_id = (
    SELECT min(a.id) FROM core_accounts a
    WHERE a.secret_name GLOB 'acct.*'
      AND a.secret_name IN (SELECT json_extract(j.value, '$.name')
                            FROM json_each(core_agent_sessions.secrets) j)
) WHERE account_id IS NULL;
