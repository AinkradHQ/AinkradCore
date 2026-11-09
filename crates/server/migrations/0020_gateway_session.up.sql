-- The auth gateway's Core side (KAN-435 G5, design 2026-11-04 §4.6, §4.7, §5.1 part 1).
--
-- `gateway_account_id` is the account whose key the session's runner serves through its gateway,
-- written by the Core when the session is created, from its own account row (never from a runner's
-- report): the ledger records a gateway session's usage against it. NULL for every other session,
-- which keeps the harness's own meter. No foreign key: the history outlives the account.
--
-- `gw_seq` is the newest gateway report the Core has recorded in the ledger, in the same transaction
-- (`AgentRead::gw_after`): the Core acknowledges exactly this and nothing newer. The runner numbers its
-- reports per session, from 1, across restarts.
--
-- `gw_stop` is why a hard-stop budget ran out for the session (set in the transaction that counted
-- the spend, so a crash cannot lose it); `gw_stopped_at` (unix seconds) is when the Core told the
-- runner to refuse and cancel it.
ALTER TABLE core_agent_sessions ADD COLUMN gateway_account_id INTEGER;
ALTER TABLE core_agent_sessions ADD COLUMN gw_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_agent_sessions ADD COLUMN gw_stop TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN gw_stopped_at INTEGER;
-- The epoch of the report `gw_seq` belongs to: a runner that lost its state renumbers from 1 under a
-- newer epoch, which is not a resend (see `store::gateway`). The ceiling the session's gateway was
-- last given (`i64::MAX` is no limit) and the price snapshot of its grant: a model that loses its price
-- in the book mid-session is still priced from what the gateway enforced, and the Core tops the
-- ceiling up (or stops the session) when the gateway has too little left for a turn.
ALTER TABLE core_agent_sessions ADD COLUMN gw_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_agent_sessions ADD COLUMN gw_ceiling_tokens INTEGER;
ALTER TABLE core_agent_sessions ADD COLUMN gw_ceiling_usd INTEGER;
ALTER TABLE core_agent_sessions ADD COLUMN gw_prices TEXT;

-- Sessions already live under an API-key account name are bound to that account's row, as the Core
-- binds a new one at create.
UPDATE core_agent_sessions SET gateway_account_id = (
    SELECT min(a.id) FROM core_accounts a
    WHERE a.secret_name GLOB 'acct.*'
      AND a.secret_name IN (SELECT json_extract(j.value, '$.name')
                            FROM json_each(core_agent_sessions.secrets) j)
) WHERE state NOT IN ('ended', 'lost');

-- An upstream `auth_failed` a gateway reported: ONE such signal never disables an account (a
-- provider's blip, a stale key in one session). It is kept here, `pending`, until a one-shot
-- `gateway.test` through a runner's gateway says what the key does now: `confirmed` (the provider
-- refuses it: the account is disabled), `cleared` (it works) or `inconclusive` (the test could not
-- say, after a few tries). `gw_key` (`gw:<session>:<epoch>:<gw_seq>`) makes a resent report a no-op.
CREATE TABLE core_account_auth_signals (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    account_id INTEGER NOT NULL,
    session    TEXT    NOT NULL CHECK (length(session) BETWEEN 1 AND 64),
    gw_key     TEXT    NOT NULL UNIQUE CHECK (length(gw_key) BETWEEN 1 AND 128),
    seen_at    TEXT    NOT NULL,
    state      TEXT    NOT NULL DEFAULT 'pending'
               CHECK (state IN ('pending', 'confirmed', 'cleared', 'inconclusive')),
    tries      INTEGER NOT NULL DEFAULT 0 CHECK (tries >= 0),
    decided_at TEXT
);

CREATE INDEX core_account_auth_signals_pending ON core_account_auth_signals (account_id)
    WHERE state = 'pending';
