-- Usage limits per provider account (E15.2). An account has any number of limits, each a
-- rolling window (`window_secs`, e.g. 5 h = 18000), a unit and a maximum: `tokens` counts
-- the account's cost events in the window, `messages` the prompts sent as it
-- (`account_events`). No vendor numbers are built in. At `warn_percent` of a limit the admin
-- is warned once per window (`warned_at`); at the limit the account becomes `limited` and is
-- skipped until the window has rolled below it.
CREATE TABLE account_limits (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    window_secs  INTEGER NOT NULL CHECK (window_secs > 0),
    unit         TEXT    NOT NULL CHECK (unit IN ('tokens', 'messages')),
    max          INTEGER NOT NULL CHECK (max > 0),
    warn_percent INTEGER NOT NULL DEFAULT 80 CHECK (warn_percent BETWEEN 1 AND 100),
    warned_at    TEXT,
    UNIQUE (account_id, window_secs, unit)
);

-- What an account was used for besides tokens: a prompt sent as it (`message`), and a
-- provider connection dropped mid-turn (`drop`, E15.4). Append-only, stamped by the caller.
CREATE TABLE account_events (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    run_id     INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('message', 'drop')),
    at         TEXT    NOT NULL
);
CREATE INDEX account_events_window ON account_events (account_id, kind, at);

-- A status the server set that ends by itself at a known time (a harness's reported reset);
-- `limited` without it lasts until the counted usage rolls out of its window. The harness's
-- latest plan-limit report, as JSON, for the usage report.
ALTER TABLE accounts ADD COLUMN status_until TEXT;
ALTER TABLE accounts ADD COLUMN signal TEXT;
