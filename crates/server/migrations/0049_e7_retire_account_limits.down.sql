-- The table comes back empty: what moved into budgets stays there.
CREATE TABLE core_account_limits (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    account_id   INTEGER NOT NULL REFERENCES core_accounts(id) ON DELETE CASCADE,
    unit         TEXT    NOT NULL CHECK (unit IN ('tokens', 'messages')),
    window_secs  INTEGER NOT NULL CHECK (window_secs BETWEEN 1 AND 31622400),
    cap          INTEGER NOT NULL CHECK (cap > 0),
    warn_percent INTEGER CHECK (warn_percent IS NULL OR warn_percent BETWEEN 1 AND 100),
    UNIQUE (account_id, unit, window_secs)
);
