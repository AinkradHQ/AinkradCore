-- Code Mode writes (plan 2026-11-13, E6). Additive only.
-- Idempotency (P7): one row per (session, key hash). `result` is NULL while the write runs or
-- when its outcome is unknown; the key is stored as a hash, never the arguments.
CREATE TABLE core_code_mode_idem (
    user_id  INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    session  TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    op       TEXT NOT NULL,
    result   TEXT,
    at       INTEGER NOT NULL,
    PRIMARY KEY (session, key_hash)
);
CREATE INDEX core_code_mode_idem_at ON core_code_mode_idem (at);

-- A risky call parked until a person decides (E6.2). `state`: pending, approved, denied, expired,
-- ended, lost (the Core restarted while it waited) or used (the one execution it allowed).
-- `args_sha256` binds the approval to the call it was asked for.
CREATE TABLE core_code_mode_approvals (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    session     TEXT NOT NULL,
    op          TEXT NOT NULL,
    reason      TEXT NOT NULL,
    summary     TEXT NOT NULL,
    args_sha256 TEXT NOT NULL,
    state       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    decided_by  TEXT,
    decided_at  INTEGER
);
CREATE INDEX core_code_mode_approvals_session ON core_code_mode_approvals (session, state);
