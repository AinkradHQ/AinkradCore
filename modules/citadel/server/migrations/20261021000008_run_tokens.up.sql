-- Per-run tokens (E4.1): only the SHA-256 of a token is stored, never the token. Its scope
-- (agent, issue, company) is read through the run, so it cannot drift from it. At most one
-- token per run is unrevoked: issuing a new one revokes the old in the same transaction.
CREATE TABLE run_tokens (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    token_hash BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    run_id     INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    expires_at TEXT    NOT NULL,
    revoked_at TEXT,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX run_tokens_one_live ON run_tokens (run_id) WHERE revoked_at IS NULL;
