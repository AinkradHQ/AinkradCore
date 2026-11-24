-- Accounts on the Core (API 103). Additive only. One row per session a Core-held plan login was lent
-- to: the account, the version of its sealed login when it was lent, and when that session's refreshed
-- login came back (once per lease). Never a credential.
CREATE TABLE core_lent_logins (
    session_id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL,
    version INTEGER NOT NULL,
    lent_at TEXT NOT NULL,
    returned_at TEXT
);
