-- Remove an account with Undo (E7 closeout). `DELETE /accounts/{id}` only marks the row: `deleted_at`, the
-- state and the pool seats it had (so an Undo can put them back). The key and the row are wiped for real
-- by `accounts::delete` when the Undo window (10 seconds) ends.
ALTER TABLE core_accounts ADD COLUMN deleted_at TEXT CHECK (deleted_at IS NULL OR julianday(deleted_at) IS NOT NULL);
-- JSON `{"state":..,"reason":..,"until":..}`: what the account was before the delete disabled it.
ALTER TABLE core_accounts ADD COLUMN deleted_prev TEXT;
-- JSON `[{"pool":1,"position":0}]`: the seats the delete took out of pools.
ALTER TABLE core_accounts ADD COLUMN deleted_seats TEXT;
CREATE INDEX core_accounts_deleted ON core_accounts (deleted_at) WHERE deleted_at IS NOT NULL;

-- A runner-bound account's login on its runner still has to be wiped when the account is gone. The Core
-- keeps what the runner needs to find it (the runner and the home key, no credential) until the runner
-- confirms; an offline runner is asked again when it is back. No FK: the account row is gone by then.
CREATE TABLE core_account_wipes (
    id         INTEGER PRIMARY KEY,
    runner     TEXT NOT NULL CHECK (length(runner) BETWEEN 1 AND 128),
    home       TEXT NOT NULL CHECK (length(home) BETWEEN 1 AND 64),
    created_at TEXT NOT NULL,
    tries      INTEGER NOT NULL DEFAULT 0,
    UNIQUE (runner, home)
);
