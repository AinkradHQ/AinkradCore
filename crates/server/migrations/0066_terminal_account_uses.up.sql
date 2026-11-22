-- An AI tool typed in a terminal signing in with an account (0.10.5). Additive only.
-- One row per lease the Core gave a terminal's runner: which account, for which tool, when. Never the
-- token. Listed with the account's AI sessions on its details page.
CREATE TABLE core_terminal_account_uses (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    terminal TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    tool TEXT NOT NULL CHECK (length(tool) BETWEEN 1 AND 32),
    runner TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX core_terminal_account_uses_account ON core_terminal_account_uses(account_id, created_at);
