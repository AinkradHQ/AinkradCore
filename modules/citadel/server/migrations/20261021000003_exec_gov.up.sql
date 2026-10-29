-- Execution (brainstorm §6) and governance (§7–§8) records. No engine logic lives here:
-- the run state machine, wake dispatch and lease expiry are E2. Rows that point at another
-- row of the same company are checked by triggers below; keys are stored as SHA-256 only.

-- Runners are infrastructure, not company-scoped.
CREATE TABLE runners (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name          TEXT    NOT NULL UNIQUE,
    key_hash      BLOB    NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    tags          TEXT    NOT NULL DEFAULT '[]'
                  CHECK (json_valid(tags) AND json_type(tags) = 'array'),
    status        TEXT    NOT NULL DEFAULT 'offline'
                  CHECK (status IN ('online', 'offline', 'unhealthy')),
    last_seen_at  TEXT,
    health_reason TEXT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((status = 'unhealthy') = (health_reason IS NOT NULL))
);

CREATE TABLE wake_requests (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    agent_id        INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    issue_id        INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    source          TEXT    NOT NULL CHECK (source IN ('assignment', 'comment', 'blocker_closed',
                    'timer', 'manual', 'approval', 'escalation', 'retry')),
    reason          TEXT    NOT NULL,
    idempotency_key TEXT    NOT NULL UNIQUE,
    coalesced_count INTEGER NOT NULL DEFAULT 0 CHECK (coalesced_count >= 0),
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'dispatched', 'coalesced', 'dropped')),
    -- Retry backoff: not dispatched before this time.
    not_before      TEXT,
    attempt         INTEGER NOT NULL DEFAULT 1 CHECK (attempt >= 1),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX wake_requests_pending ON wake_requests (agent_id, issue_id) WHERE status = 'pending';
CREATE INDEX wake_requests_issue ON wake_requests (issue_id);

-- An unknown price is NULL with priced = 0, never 0 (#15, E7.3).
CREATE TABLE runs (
    id                  INTEGER PRIMARY KEY,
    user_id             INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    agent_id            INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    issue_id            INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    wake_request_id     INTEGER REFERENCES wake_requests(id) ON DELETE SET NULL,
    runner_id           INTEGER REFERENCES runners(id) ON DELETE SET NULL,
    state               TEXT    NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'claimed',
                        'running', 'succeeded', 'failed', 'cancelled', 'timed_out', 'runner_lost')),
    terminal_reason     TEXT    CHECK (terminal_reason <> ''),
    harness             TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    harness_version     TEXT,
    session_id          TEXT,
    input_tokens        INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens       INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cache_tokens        INTEGER NOT NULL DEFAULT 0 CHECK (cache_tokens >= 0),
    cost_usd_micros     INTEGER CHECK (cost_usd_micros >= 0),
    priced              INTEGER NOT NULL DEFAULT 0 CHECK (priced IN (0, 1)),
    queued_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    claimed_at          TEXT,
    started_at          TEXT,
    ended_at            TEXT,
    failure_fingerprint TEXT,
    -- Every terminal run says why (#4); a live run has no reason yet.
    CHECK ((state IN ('queued', 'claimed', 'running')) = (terminal_reason IS NULL)),
    CHECK (priced = (cost_usd_micros IS NOT NULL))
);
CREATE INDEX runs_agent ON runs (agent_id);
CREATE INDEX runs_issue ON runs (issue_id);
CREATE INDEX runs_runner ON runs (runner_id);
CREATE INDEX runs_wake_request ON runs (wake_request_id);
CREATE INDEX runs_live ON runs (state) WHERE state IN ('queued', 'claimed', 'running');

CREATE TABLE leases (
    run_id       INTEGER PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    runner_id    INTEGER NOT NULL REFERENCES runners(id) ON DELETE CASCADE,
    expires_at   TEXT    NOT NULL,
    heartbeat_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX leases_runner ON leases (runner_id);
CREATE INDEX leases_expiry ON leases (expires_at);

-- Insert-only ledger (a trigger rejects edits); the issue link may still clear on delete.
CREATE TABLE cost_events (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    run_id          INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    agent_id        INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    issue_id        INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    input_tokens    INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens   INTEGER NOT NULL CHECK (output_tokens >= 0),
    cache_tokens    INTEGER NOT NULL CHECK (cache_tokens >= 0),
    cost_usd_micros INTEGER CHECK (cost_usd_micros >= 0),
    priced          INTEGER NOT NULL CHECK (priced IN (0, 1)),
    idempotency_key TEXT    NOT NULL UNIQUE,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (priced = (cost_usd_micros IS NOT NULL))
);
CREATE INDEX cost_events_run ON cost_events (run_id);
CREATE INDEX cost_events_agent ON cost_events (agent_id);
CREATE INDEX cost_events_issue ON cost_events (issue_id);

CREATE TABLE approvals (
    id                      INTEGER PRIMARY KEY,
    user_id                 INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id              INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    kind                    TEXT    NOT NULL CHECK (kind IN ('sprint_commit', 'pr_merge',
                            'budget_overrun', 'hire_agent', 'permission_escalation')),
    -- Subjects; an approval outlives them.
    issue_id                INTEGER REFERENCES issues(id) ON DELETE SET NULL,
    sprint_id               INTEGER REFERENCES sprints(id) ON DELETE SET NULL,
    agent_id                INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    -- The requester cannot be deleted while it has approvals (terminate it instead).
    requested_by_agent_id   INTEGER NOT NULL REFERENCES agents(id),
    status                  TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'rejected')),
    decided_by_user_id      INTEGER REFERENCES users(id),
    reply                   TEXT,
    payload                 TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((status = 'pending') = (decided_by_user_id IS NULL))
);
CREATE INDEX approvals_pending ON approvals (company_id) WHERE status = 'pending';
CREATE INDEX approvals_requested_by ON approvals (requested_by_agent_id);
CREATE INDEX approvals_issue ON approvals (issue_id);
CREATE INDEX approvals_sprint ON approvals (sprint_id);
CREATE INDEX approvals_agent ON approvals (agent_id);

-- The scope's own id column is set, the rest are NULL; scope_id is whichever is set.
-- A budget goes with its scope.
CREATE TABLE budgets (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    scope           TEXT    NOT NULL
                    CHECK (scope IN ('company', 'department', 'project', 'agent', 'sprint')),
    company_id      INTEGER REFERENCES companies(id) ON DELETE CASCADE,
    department_id   INTEGER REFERENCES departments(id) ON DELETE CASCADE,
    project_id      INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    agent_id        INTEGER REFERENCES agents(id) ON DELETE CASCADE,
    sprint_id       INTEGER REFERENCES sprints(id) ON DELETE CASCADE,
    scope_id        INTEGER GENERATED ALWAYS AS
                    (coalesce(company_id, department_id, project_id, agent_id, sprint_id)) VIRTUAL,
    period          TEXT    NOT NULL CHECK (period IN ('day', 'week', 'month', 'total')),
    token_cap       INTEGER NOT NULL CHECK (token_cap >= 0),
    warn_at_percent INTEGER NOT NULL DEFAULT 80 CHECK (warn_at_percent BETWEEN 1 AND 100),
    hard_stop       INTEGER NOT NULL DEFAULT 1 CHECK (hard_stop IN (0, 1)),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((company_id IS NOT NULL) = (scope = 'company')),
    CHECK ((department_id IS NOT NULL) = (scope = 'department')),
    CHECK ((project_id IS NOT NULL) = (scope = 'project')),
    CHECK ((agent_id IS NOT NULL) = (scope = 'agent')),
    CHECK ((sprint_id IS NOT NULL) = (scope = 'sprint')),
    UNIQUE (scope, scope_id, period)
);

-- Attached to the whole company, or to one department / role / project within it.
CREATE TABLE skills (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id    INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    version       INTEGER NOT NULL CHECK (version >= 1),
    body          TEXT    NOT NULL,
    attach_scope  TEXT    NOT NULL
                  CHECK (attach_scope IN ('company', 'department', 'role', 'project')),
    department_id INTEGER REFERENCES departments(id) ON DELETE CASCADE,
    role          TEXT,
    project_id    INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((department_id IS NOT NULL) = (attach_scope = 'department')),
    CHECK ((role IS NOT NULL) = (attach_scope = 'role')),
    CHECK ((project_id IS NOT NULL) = (attach_scope = 'project')),
    UNIQUE (company_id, name, version)
);
CREATE INDEX skills_department ON skills (department_id);
CREATE INDEX skills_project ON skills (project_id);

CREATE TABLE knowledge_entries (
    id                   INTEGER PRIMARY KEY,
    user_id              INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id           INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind                 TEXT    NOT NULL CHECK (kind IN ('decision', 'landmine', 'state', 'retro')),
    title                TEXT    NOT NULL,
    body                 TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'proposed'
                         CHECK (status IN ('proposed', 'accepted', 'rejected')),
    -- NULL when a human wrote it.
    proposed_by_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    decided_by_user_id   INTEGER REFERENCES users(id),
    created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((status = 'proposed') = (decided_by_user_id IS NULL))
);
CREATE INDEX knowledge_entries_project ON knowledge_entries (project_id, status);
CREATE INDEX knowledge_entries_proposed_by ON knowledge_entries (proposed_by_agent_id);

CREATE TABLE device_keys (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name         TEXT    NOT NULL,
    key_hash     BLOB    NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT,
    revoked_at   TEXT
);

-- comments.run_id was plain text until runs existed (E1.3). Rebuild the table so it
-- references runs; no run ids exist yet, so the placeholder values are dropped.
CREATE TABLE comments_new (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    issue_id        INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    author_agent_id INTEGER REFERENCES agents(id),
    author_user_id  INTEGER REFERENCES users(id),
    body            TEXT    NOT NULL,
    -- The run that wrote it; the comment outlives the run.
    run_id          INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    idempotency_key TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((author_agent_id IS NULL) <> (author_user_id IS NULL)),
    UNIQUE (issue_id, idempotency_key)
);
INSERT INTO comments_new
    (id, user_id, issue_id, author_agent_id, author_user_id, body, run_id, idempotency_key,
     created_at)
SELECT id, user_id, issue_id, author_agent_id, author_user_id, body, NULL, idempotency_key,
       created_at
FROM comments;
DROP TABLE comments;
ALTER TABLE comments_new RENAME TO comments;
CREATE INDEX comments_author_agent ON comments (author_agent_id);
CREATE INDEX comments_run ON comments (run_id);

-- Same-company rules. `<>` against a missing row yields NULL, so a dangling id falls
-- through to its foreign key error instead.

CREATE TRIGGER runs_same_company BEFORE INSERT ON runs
BEGIN
    SELECT RAISE(ABORT, 'issue belongs to another company')
    WHERE (SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id
           WHERE i.id = NEW.issue_id)
       <> (SELECT company_id FROM agents WHERE id = NEW.agent_id);
END;

CREATE TRIGGER wake_requests_same_company BEFORE INSERT ON wake_requests
BEGIN
    SELECT RAISE(ABORT, 'issue belongs to another company')
    WHERE (SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id
           WHERE i.id = NEW.issue_id)
       <> (SELECT company_id FROM agents WHERE id = NEW.agent_id);
END;

CREATE TRIGGER cost_events_match_run BEFORE INSERT ON cost_events
BEGIN
    SELECT RAISE(ABORT, 'cost event does not match its run')
    WHERE EXISTS (SELECT 1 FROM runs WHERE id = NEW.run_id
                  AND (agent_id <> NEW.agent_id OR issue_id IS NOT NEW.issue_id));
END;

-- issue_id is left out so ON DELETE SET NULL still works.
CREATE TRIGGER cost_events_insert_only
BEFORE UPDATE OF id, user_id, run_id, agent_id, input_tokens, output_tokens, cache_tokens,
    cost_usd_micros, priced, idempotency_key, created_at ON cost_events
BEGIN
    SELECT RAISE(ABORT, 'cost events are insert-only');
END;

CREATE TRIGGER approvals_same_company BEFORE INSERT ON approvals
BEGIN
    SELECT RAISE(ABORT, 'requester belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.requested_by_agent_id)
       <> NEW.company_id;
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.agent_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'issue belongs to another company')
    WHERE (SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id
           WHERE i.id = NEW.issue_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'sprint belongs to another company')
    WHERE (SELECT p.company_id FROM sprints s JOIN projects p ON p.id = s.project_id
           WHERE s.id = NEW.sprint_id) <> NEW.company_id;
END;

CREATE TRIGGER skills_same_company_insert BEFORE INSERT ON skills
BEGIN
    SELECT RAISE(ABORT, 'department belongs to another company')
    WHERE (SELECT company_id FROM departments WHERE id = NEW.department_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'project belongs to another company')
    WHERE (SELECT company_id FROM projects WHERE id = NEW.project_id) <> NEW.company_id;
END;

CREATE TRIGGER skills_same_company_update
BEFORE UPDATE OF company_id, department_id, project_id ON skills
BEGIN
    SELECT RAISE(ABORT, 'department belongs to another company')
    WHERE (SELECT company_id FROM departments WHERE id = NEW.department_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'project belongs to another company')
    WHERE (SELECT company_id FROM projects WHERE id = NEW.project_id) <> NEW.company_id;
END;

CREATE TRIGGER knowledge_entries_same_company BEFORE INSERT ON knowledge_entries
BEGIN
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.proposed_by_agent_id)
       <> (SELECT company_id FROM projects WHERE id = NEW.project_id);
END;
