-- The admin's controls (decision #34, runner protocol 1.19).
--
-- An agent the admin paused keeps `paused_at` until resumed: its issues wait on it by design, so
-- the stuck detector leaves them alone (a loop-breaker pause sets no `paused_at`).
ALTER TABLE agents ADD COLUMN paused_at TEXT;
-- A runner the admin asked to wake (a sleeping Mac): set until it next says hello.
ALTER TABLE runners ADD COLUMN wake_requested_at TEXT;

-- What a run's runner is told by the admin: `pause` (finish the tool call, then end), `stop`
-- (end now; the run is already cancelled) and `message` (the harness's next turn). Each goes to
-- the runner holding the run once (`sent_at`); a message is `delivered_at` when the runner gave
-- it to the harness, else it becomes a comment on the run's issue when the run ends.
CREATE TABLE run_controls (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind            TEXT    NOT NULL CHECK (kind IN ('pause', 'stop', 'message')),
    body            TEXT    NOT NULL DEFAULT '',
    idempotency_key TEXT,
    created_at      TEXT    NOT NULL,
    sent_at         TEXT,
    delivered_at    TEXT,
    comment_id      INTEGER REFERENCES comments(id) ON DELETE SET NULL,
    UNIQUE (run_id, idempotency_key)
);
CREATE INDEX run_controls_unsent ON run_controls (run_id) WHERE sent_at IS NULL;

-- "Allow for this issue" on a permission escalation: an allowlist entry (`<tool>` or
-- `<tool>:<command prefix>`) for the issue's runs until it expires.
CREATE TABLE issue_allow_rules (
    id          INTEGER PRIMARY KEY,
    issue_id    INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    rule        TEXT    NOT NULL CHECK (rule <> ''),
    approval_id INTEGER REFERENCES approvals(id) ON DELETE SET NULL,
    created_at  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL
);
CREATE INDEX issue_allow_rules_issue ON issue_allow_rules (issue_id);
