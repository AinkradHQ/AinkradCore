-- citadel_0002_accounts: provider account pool (S9) and company notification preferences (S11).
-- Credentials live in the Core secrets broker (`core_secrets`); `citadel_accounts` stores only the
-- broker's secret name and delivery/runner scope metadata, never a credential value or path.

CREATE TABLE citadel_accounts (
    id            INTEGER PRIMARY KEY,
    harness       TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    label         TEXT    NOT NULL UNIQUE CHECK (length(label) BETWEEN 1 AND 64),
    secret_name   TEXT    NOT NULL UNIQUE CHECK (length(secret_name) BETWEEN 1 AND 64),
    delivery      TEXT    NOT NULL DEFAULT 'env' CHECK (delivery IN ('env', 'file', 'askpass')),
    runners       TEXT    NOT NULL DEFAULT '[]'
                  CHECK (json_valid(runners) AND json_type(runners) = 'array'),
    billing       TEXT    NOT NULL DEFAULT 'subscription'
                  CHECK (billing IN ('subscription', 'metered')),
    config_dir    TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'cooling', 'limited', 'unhealthy', 'disabled')),
    status_reason TEXT,
    status_until  TEXT    CHECK (status_until IS NULL OR julianday(status_until) IS NOT NULL),
    last_used_at  TEXT,
    plan_tier     TEXT    CHECK (plan_tier IS NULL OR length(plan_tier) BETWEEN 1 AND 64),
    signal        TEXT    CHECK (signal IS NULL OR json_valid(signal)),
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE citadel_account_companies (
    account_id INTEGER NOT NULL REFERENCES citadel_accounts(id) ON DELETE CASCADE,
    company_id INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    PRIMARY KEY (account_id, company_id)
) STRICT;

CREATE INDEX citadel_account_companies_company ON citadel_account_companies (company_id);

CREATE TABLE citadel_account_limits (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES citadel_accounts(id) ON DELETE CASCADE,
    window_secs  INTEGER NOT NULL CHECK (window_secs > 0),
    unit         TEXT    NOT NULL CHECK (unit IN ('tokens', 'messages')),
    cap          INTEGER NOT NULL CHECK (cap > 0),
    warn_percent INTEGER CHECK (warn_percent IS NULL OR warn_percent BETWEEN 1 AND 100),
    warned_at    TEXT,
    UNIQUE (account_id, unit, window_secs)
) STRICT;

CREATE TABLE citadel_account_events (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES citadel_accounts(id) ON DELETE CASCADE,
    run_id     INTEGER,
    kind       TEXT    NOT NULL CHECK (kind IN ('message', 'drop')),
    at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX citadel_account_events_window ON citadel_account_events (account_id, kind, at);

CREATE TABLE citadel_notification_prefs (
    company_id INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    event      TEXT    NOT NULL CHECK (event <> ''),
    channel    TEXT    NOT NULL CHECK (channel <> ''),
    enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    PRIMARY KEY (company_id, event, channel)
) STRICT;

CREATE TABLE citadel_notification_quiet (
    company_id   INTEGER PRIMARY KEY REFERENCES citadel_companies(id) ON DELETE CASCADE,
    quiet_start  INTEGER NOT NULL DEFAULT 1320 CHECK (quiet_start BETWEEN 0 AND 1439),
    quiet_end    INTEGER NOT NULL DEFAULT 420 CHECK (quiet_end BETWEEN 0 AND 1439),
    quiet_on     INTEGER NOT NULL DEFAULT 0 CHECK (quiet_on IN (0, 1)),
    breakthrough TEXT    NOT NULL DEFAULT 'stalled' CHECK (breakthrough IN ('stalled', 'nothing'))
) STRICT;
