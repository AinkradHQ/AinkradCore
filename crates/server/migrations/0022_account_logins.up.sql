-- Subscription sign-ins (KAN-441, plan 2026-11-05-claude-subscription-sign-in, story L1).
--
-- A login is STATE ONLY: where a one-shot sign-in on a runner has got to. It never holds a token,
-- an approval code or a sign-in URL's secret parts beyond the public authorize URL; the token goes
-- straight from the runner into the secrets broker. It is transient, so a backup and an export
-- drop every row (`ops::backup::drop_logins`).
CREATE TABLE core_account_logins (
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    id         TEXT PRIMARY KEY CHECK (length(id) BETWEEN 4 AND 64),
    provider   TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 32),
    label      TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 64),
    runner     TEXT NOT NULL,
    -- The device that asked; only it may send the code.
    device     TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('starting', 'open_url', 'waiting_code', 'storing',
                                              'done', 'failed', 'cancelled')),
    url        TEXT CHECK (url IS NULL OR length(url) <= 2048),
    account_id INTEGER,
    reason     TEXT CHECK (reason IS NULL OR length(reason) <= 200),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX core_account_logins_state ON core_account_logins (state);

-- A subscription provider (`claude-sub`) has pools too, so the pool's three-name provider CHECK goes,
-- the way `core_accounts.provider` lost its own (0021): a column's CHECK is dropped with the column, and
-- the table is not rebuilt (the seats and bindings that reference it would be cascaded away).
DROP INDEX core_pools_one_default;
ALTER TABLE core_pools ADD COLUMN provider_id TEXT NOT NULL DEFAULT 'anthropic'
    CHECK (length(provider_id) BETWEEN 1 AND 32 AND substr(provider_id, 1, 1) GLOB '[a-z]'
           AND provider_id NOT GLOB '*[^a-z0-9-]*');
UPDATE core_pools SET provider_id = provider;
ALTER TABLE core_pools DROP COLUMN provider;
ALTER TABLE core_pools RENAME COLUMN provider_id TO provider;
CREATE UNIQUE INDEX core_pools_one_default ON core_pools (provider) WHERE is_default = 1;
