-- Retire the per-account rolling limits (`core_account_limits`): a limit is a budget now. Every window
-- maps to the NEAREST STRICTER budget period, never a looser one: under 1 day = `hour5` (the shortest
-- there is), 1 day up to 7 days = `day`, 7 days up to 30 days = `week`, longer = `month`. So 5 hours,
-- 1 day and 7 days land exactly on `hour5`, `day` and `week`. A tokens limit becomes `token_cap`, a
-- messages limit `message_cap`, the warning carries over. Limits that land on one period merge, and
-- one that meets an existing budget of the same account and period merges with it the same way: the
-- smaller non-zero cap wins for tokens and for messages, the warning is the smaller, `hard_stop` is
-- the larger. No limit is dropped. `core_limit_retired` keeps each converted limit with the period it
-- became so the Core writes one audit row per limit at its next start (`accounts::retired_limits`,
-- which drops the table after); SQL cannot append to the hash-chained audit log.
CREATE TABLE core_limit_retired (
    user_id      INTEGER NOT NULL,
    account_id   INTEGER NOT NULL,
    unit         TEXT    NOT NULL,
    window_secs  INTEGER NOT NULL,
    cap          INTEGER NOT NULL,
    warn_percent INTEGER,
    period       TEXT
);
INSERT INTO core_limit_retired (user_id, account_id, unit, window_secs, cap, warn_percent, period)
    SELECT user_id, account_id, unit, window_secs, cap, warn_percent,
           CASE WHEN window_secs < 86400 THEN 'hour5'
                WHEN window_secs < 604800 THEN 'day'
                WHEN window_secs < 2592000 THEN 'week'
                ELSE 'month' END
    FROM core_account_limits;
INSERT INTO core_budgets (user_id, subject_kind, subject_id, period, token_cap, message_cap,
        warn_at_percent, hard_stop, created_at, updated_at)
    SELECT user_id, 'account', CAST(account_id AS TEXT), period,
           coalesce(min(CASE WHEN unit = 'tokens' THEN cap END), 0),
           min(CASE WHEN unit = 'messages' THEN cap END),
           min(coalesce(warn_percent, 80)), 1,
           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM core_limit_retired WHERE period IS NOT NULL
    GROUP BY user_id, account_id, period
    ON CONFLICT (subject_kind, subject_id, period) DO UPDATE SET
        token_cap = CASE WHEN core_budgets.token_cap = 0 THEN excluded.token_cap
                         WHEN excluded.token_cap = 0 THEN core_budgets.token_cap
                         WHEN excluded.token_cap < core_budgets.token_cap THEN excluded.token_cap
                         ELSE core_budgets.token_cap END,
        message_cap = CASE WHEN core_budgets.message_cap IS NULL THEN excluded.message_cap
                           WHEN excluded.message_cap IS NULL THEN core_budgets.message_cap
                           WHEN excluded.message_cap < core_budgets.message_cap THEN excluded.message_cap
                           ELSE core_budgets.message_cap END,
        warn_at_percent = min(core_budgets.warn_at_percent, excluded.warn_at_percent),
        hard_stop = max(core_budgets.hard_stop, excluded.hard_stop),
        updated_at = excluded.updated_at;
DROP TABLE core_account_limits;
