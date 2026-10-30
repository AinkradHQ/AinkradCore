-- citadel_0003_runs: the run engine (S7). A run is one wake of one agent on one issue; its
-- harness is an agent session of the platform (`session_id`, `as_...`), which holds the
-- transcript, the lease and the supervision. No FK into `core_*`: the guard keeps a module's
-- schema its own, and the engine reads the session through the Core's store.

CREATE TABLE citadel_wake_requests (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    agent_id        INTEGER NOT NULL REFERENCES citadel_agents(id) ON DELETE CASCADE,
    issue_id        INTEGER REFERENCES citadel_issues(id) ON DELETE SET NULL,
    source          TEXT    NOT NULL CHECK (source IN ('assignment', 'comment', 'blocker_closed',
                    'timer', 'manual', 'approval', 'escalation', 'retry')),
    reason          TEXT    NOT NULL,
    idempotency_key TEXT    NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    coalesced_count INTEGER NOT NULL DEFAULT 0 CHECK (coalesced_count >= 0),
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'dispatched', 'coalesced', 'dropped')),
    not_before      TEXT    CHECK (not_before IS NULL OR julianday(not_before) IS NOT NULL),
    attempt         INTEGER NOT NULL DEFAULT 1 CHECK (attempt >= 1),
    coalesced_into  INTEGER REFERENCES citadel_wake_requests(id) ON DELETE SET NULL,
    dropped_reason  TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((status = 'dropped') = (dropped_reason IS NOT NULL))
) STRICT;

CREATE INDEX citadel_wake_requests_due ON citadel_wake_requests (status, not_before)
    WHERE status = 'pending';

CREATE TABLE citadel_runs (
    id                  INTEGER PRIMARY KEY,
    user_id             INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    agent_id            INTEGER NOT NULL REFERENCES citadel_agents(id) ON DELETE CASCADE,
    issue_id            INTEGER REFERENCES citadel_issues(id) ON DELETE SET NULL,
    wake_request_id     INTEGER REFERENCES citadel_wake_requests(id) ON DELETE SET NULL,
    session_id          TEXT    UNIQUE CHECK (session_id IS NULL OR session_id GLOB 'as_*'),
    runner              TEXT,
    state               TEXT    NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'claimed',
                        'running', 'succeeded', 'failed', 'cancelled', 'timed_out',
                        'runner_lost')),
    terminal_reason     TEXT,
    harness             TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model_used          TEXT,
    input_tokens        INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens       INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cache_tokens        INTEGER NOT NULL DEFAULT 0 CHECK (cache_tokens >= 0),
    cost_usd_micros     INTEGER CHECK (cost_usd_micros >= 0),
    priced              INTEGER NOT NULL DEFAULT 0 CHECK (priced IN (0, 1)),
    failure_fingerprint TEXT,
    cancel_requested_at TEXT,
    -- The last transcript entry of the session already looked at for tool approvals.
    approval_seq        INTEGER NOT NULL DEFAULT 0 CHECK (approval_seq >= 0),
    queued_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    claimed_at          TEXT,
    started_at          TEXT,
    ended_at            TEXT,
    CHECK ((state IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'runner_lost'))
           = (terminal_reason IS NOT NULL)),
    CHECK (priced = (cost_usd_micros IS NOT NULL))
) STRICT;

CREATE INDEX citadel_runs_live ON citadel_runs (state) WHERE state IN ('queued', 'claimed', 'running');
CREATE INDEX citadel_runs_issue ON citadel_runs (issue_id);
CREATE INDEX citadel_runs_agent ON citadel_runs (agent_id);

-- A run's token for its agent's callbacks (the MCP server, S8): only its SHA-256 is stored.
CREATE TABLE citadel_run_tokens (
    token_hash TEXT    PRIMARY KEY CHECK (length(token_hash) = 64),
    run_id     INTEGER NOT NULL REFERENCES citadel_runs(id) ON DELETE CASCADE,
    issued_at  TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    revoked_at TEXT
) STRICT;

-- At most one live token per run.
CREATE UNIQUE INDEX citadel_run_tokens_live ON citadel_run_tokens (run_id) WHERE revoked_at IS NULL;

-- The operator's standing authorisation for the engine to start runs on its own: one row. The
-- device that last enabled it (a step-up route) is the accountable creator of the sessions.
CREATE TABLE citadel_engine (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    by_device  TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
) STRICT;
