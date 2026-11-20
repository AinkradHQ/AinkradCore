-- A runner-bound subscription account (E7-4, E7-5, E7-5b): its login (Codex auth.json, OpenCode
-- auth.json, Antigravity's keyring entry) lives in a home on one runner and never leaves it. The
-- Core keeps only which runner and which home key, no token. The account's broker secret holds a
-- non-secret marker and is scoped to that one runner, so the allocator places the session there.
CREATE TABLE core_account_bound (
    account_id INTEGER PRIMARY KEY REFERENCES core_accounts(id) ON DELETE CASCADE,
    runner     TEXT NOT NULL CHECK (length(runner) BETWEEN 1 AND 128),
    home       TEXT NOT NULL CHECK (length(home) BETWEEN 1 AND 64),
    created_at TEXT NOT NULL
);

-- The one-time device code a Codex sign-in shows beside its URL: not a credential, shown to the user.
ALTER TABLE core_account_logins ADD COLUMN code TEXT CHECK (code IS NULL OR length(code) <= 32);
