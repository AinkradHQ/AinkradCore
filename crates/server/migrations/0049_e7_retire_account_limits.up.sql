-- Retire the per-account rolling limits (`core_account_limits`): a limit is a budget now. A stored limit
-- maps to a budget of the same account only when its window is one a budget has (5 hours = `hour5`,
-- 1 day, 7 days = `week`): a tokens limit becomes `token_cap`, a messages limit `message_cap`, the warning
-- carries over. Any other window has no budget period and is dropped. A budget already there for the
-- same account and period wins: its tokens stay, and a message cap only fills an empty one.
INSERT INTO core_budgets (user_id, subject_kind, subject_id, period, token_cap, message_cap,
        warn_at_percent, hard_stop, created_at, updated_at)
    SELECT user_id, 'account', CAST(account_id AS TEXT),
           CASE window_secs WHEN 18000 THEN 'hour5' WHEN 86400 THEN 'day' ELSE 'week' END,
           cap, NULL, coalesce(warn_percent, 80), 1,
           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM core_account_limits WHERE unit = 'tokens' AND window_secs IN (18000, 86400, 604800)
    ON CONFLICT (subject_kind, subject_id, period) DO NOTHING;
INSERT INTO core_budgets (user_id, subject_kind, subject_id, period, token_cap, message_cap,
        warn_at_percent, hard_stop, created_at, updated_at)
    SELECT user_id, 'account', CAST(account_id AS TEXT),
           CASE window_secs WHEN 18000 THEN 'hour5' WHEN 86400 THEN 'day' ELSE 'week' END,
           0, cap, coalesce(warn_percent, 80), 1,
           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    FROM core_account_limits WHERE unit = 'messages' AND window_secs IN (18000, 86400, 604800)
    ON CONFLICT (subject_kind, subject_id, period)
    DO UPDATE SET message_cap = coalesce(core_budgets.message_cap, excluded.message_cap);
DROP TABLE core_account_limits;
