-- The platform scheduler (E2-11) and the push-token registry (E2-12).
--
-- `core_jobs` is one row per job a module (or the platform) registers; `core_job_runs` one row per
-- run of it. A run is created once per occurrence: `(job_id, idem_key)` is unique, so a schedule
-- tick, a restart or a repeated wake cannot queue the same occurrence twice. A run is claimed by a
-- lease (`holder`, `lease_until`) that its worker extends while it works; a lease that expires
-- hands the run to the next worker (at-least-once), and `idem_key` is what the handler dedupes on.

CREATE TABLE core_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    owner        TEXT    NOT NULL CHECK (owner <> ''),
    name         TEXT    NOT NULL CHECK (name <> ''),
    -- `spec`: the cron expression (`cron`), whole seconds (`every`), an RFC 3339 time (`once`),
    -- empty for a `wake` job, which only runs when something wakes it.
    kind         TEXT    NOT NULL CHECK (kind IN ('cron', 'every', 'once', 'wake')),
    spec         TEXT    NOT NULL,
    -- What a schedule that came due while the Core was down does: one run, or none.
    missed       TEXT    NOT NULL DEFAULT 'run_once' CHECK (missed IN ('run_once', 'skip')),
    grace_secs   INTEGER NOT NULL DEFAULT 60 CHECK (grace_secs BETWEEN 0 AND 86400),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
    backoff_secs INTEGER NOT NULL DEFAULT 30 CHECK (backoff_secs BETWEEN 1 AND 3600),
    enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    -- The next occurrence; NULL once a `once` job has fired and for a `wake` job.
    next_at      TEXT,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (owner, name)
);

CREATE INDEX core_jobs_due ON core_jobs (next_at) WHERE enabled = 1 AND next_at IS NOT NULL;

CREATE TABLE core_job_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    job_id      INTEGER NOT NULL REFERENCES core_jobs(id) ON DELETE CASCADE,
    idem_key    TEXT    NOT NULL CHECK (idem_key <> ''),
    payload     TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),
    status      TEXT    NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'ok', 'dead')),
    -- The occurrence it is for, and the earliest time it may start (a retry waits out its backoff).
    due_at      TEXT    NOT NULL,
    run_at      TEXT    NOT NULL,
    attempt     INTEGER NOT NULL DEFAULT 0,
    holder      TEXT,
    lease_until TEXT,
    error       TEXT,
    started_at  TEXT,
    finished_at TEXT,
    UNIQUE (job_id, idem_key)
);

CREATE INDEX core_job_runs_ready ON core_job_runs (run_at) WHERE status = 'queued';
CREATE INDEX core_job_runs_leased ON core_job_runs (lease_until) WHERE status = 'running';
CREATE INDEX core_job_runs_finished ON core_job_runs (finished_at) WHERE finished_at IS NOT NULL;

-- Where a device gets pushes: at most one token per provider per device, and a token belongs to
-- one device. The row goes with the device's revocation (`revoke_in`) and with a failing token
-- (`failures`, `push::deliver`). The APNs columns on `core_devices` are no longer read.
CREATE TABLE core_push_tokens (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    device_seq INTEGER NOT NULL REFERENCES core_devices(seq) ON DELETE CASCADE,
    provider   TEXT    NOT NULL CHECK (provider IN ('apns', 'fcm', 'webpush')),
    token      TEXT    NOT NULL CHECK (length(token) BETWEEN 8 AND 4096),
    -- APNs only: a development build's token goes to the sandbox gateway.
    sandbox    INTEGER NOT NULL DEFAULT 0 CHECK (sandbox IN (0, 1)),
    -- Consecutive failed deliveries; reset by a success.
    failures   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (device_seq, provider),
    UNIQUE (provider, token)
);

INSERT INTO core_push_tokens (device_seq, provider, token, sandbox)
SELECT seq, 'apns', push_token, push_sandbox FROM core_devices
WHERE push_token IS NOT NULL AND status = 'active' AND revoked_at IS NULL;
