-- Account limits for the Accounts screen (E7-2): a `hour5` window (fixed 5-hour UTC buckets, aligned to
-- the Unix epoch: 00:00 UTC of 1970-01-01 plus a multiple of 5 hours) and a message cap (one cost event
-- is one message; a billing correction is none). `period` is a column CHECK, so `core_budgets` is rebuilt.
-- Its two children reference it with ON DELETE CASCADE, and dropping a parent deletes its children, so
-- all three are copied aside, dropped children first, recreated and refilled. Nothing else references them.
CREATE TABLE core_budgets_bak AS SELECT * FROM core_budgets;
CREATE TABLE core_budget_spend_bak AS SELECT * FROM core_budget_spend;
CREATE TABLE core_budget_holds_bak AS SELECT * FROM core_budget_holds;
CREATE TABLE core_budgets_seq AS SELECT seq FROM sqlite_sequence WHERE name = 'core_budgets';
DROP TABLE core_budget_holds;
DROP TABLE core_budget_spend;
DROP TABLE core_budgets;

CREATE TABLE core_budgets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    subject_kind    TEXT    NOT NULL CHECK (subject_kind IN
                    ('account', 'pool', 'agent', 'company', 'department', 'project', 'sprint', 'issue')),
    subject_id      TEXT    NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 64),
    company         TEXT    CHECK (company IS NULL OR length(company) BETWEEN 1 AND 64),
    period          TEXT    NOT NULL CHECK (period IN ('hour5', 'day', 'week', 'month', 'total')),
    token_cap       INTEGER NOT NULL CHECK (token_cap >= 0),
    usd_cap_micros  INTEGER CHECK (usd_cap_micros >= 0),
    warn_at_percent INTEGER NOT NULL DEFAULT 80 CHECK (warn_at_percent BETWEEN 1 AND 100),
    hard_stop       INTEGER NOT NULL DEFAULT 1 CHECK (hard_stop IN (0, 1)),
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    message_cap     INTEGER CHECK (message_cap >= 1),
    CHECK (subject_kind <> 'company' OR company = subject_id),
    UNIQUE (subject_kind, subject_id, period)
);
CREATE INDEX core_budgets_company ON core_budgets (company) WHERE company IS NOT NULL;

CREATE TABLE core_budget_spend (
    user_id           INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    budget_id         INTEGER NOT NULL REFERENCES core_budgets(id) ON DELETE CASCADE,
    period_key        TEXT    NOT NULL CHECK (period_key <> ''),
    tokens            INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    usd_micros        INTEGER NOT NULL DEFAULT 0,
    raised            INTEGER NOT NULL DEFAULT 0 CHECK (raised >= 0),
    raised_usd_micros INTEGER NOT NULL DEFAULT 0 CHECK (raised_usd_micros >= 0),
    warned_at         TEXT,
    exhausted_at      TEXT,
    messages          INTEGER NOT NULL DEFAULT 0 CHECK (messages >= 0),
    PRIMARY KEY (budget_id, period_key)
) WITHOUT ROWID;

CREATE TABLE core_budget_holds (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    session    TEXT    NOT NULL CHECK (length(session) BETWEEN 1 AND 64),
    budget_id  INTEGER NOT NULL REFERENCES core_budgets(id) ON DELETE CASCADE,
    period_key TEXT    NOT NULL CHECK (period_key <> ''),
    tokens     INTEGER NOT NULL CHECK (tokens >= 0),
    usd_micros INTEGER NOT NULL CHECK (usd_micros >= 0),
    expires_at TEXT    NOT NULL CHECK (julianday(expires_at) IS NOT NULL),
    created_at TEXT    NOT NULL,
    UNIQUE (session, budget_id)
);
CREATE INDEX core_budget_holds_budget ON core_budget_holds (budget_id, period_key);

INSERT INTO core_budgets (id, user_id, subject_kind, subject_id, company, period, token_cap,
        usd_cap_micros, warn_at_percent, hard_stop, created_at, updated_at)
    SELECT id, user_id, subject_kind, subject_id, company, period, token_cap, usd_cap_micros,
           warn_at_percent, hard_stop, created_at, updated_at FROM core_budgets_bak;
INSERT INTO core_budget_spend (user_id, budget_id, period_key, tokens, usd_micros, raised,
        raised_usd_micros, warned_at, exhausted_at)
    SELECT user_id, budget_id, period_key, tokens, usd_micros, raised, raised_usd_micros, warned_at,
           exhausted_at FROM core_budget_spend_bak;
INSERT INTO core_budget_holds (id, user_id, session, budget_id, period_key, tokens, usd_micros,
        expires_at, created_at)
    SELECT id, user_id, session, budget_id, period_key, tokens, usd_micros, expires_at, created_at
    FROM core_budget_holds_bak;
DROP TABLE core_budget_holds_bak;
DROP TABLE core_budget_spend_bak;
DROP TABLE core_budgets_bak;

-- AUTOINCREMENT: a deleted budget's id is still never reused, so carry the old counter over.
DELETE FROM sqlite_sequence WHERE name = 'core_budgets';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'core_budgets', max(coalesce((SELECT seq FROM core_budgets_seq), 0),
                               coalesce((SELECT max(id) FROM core_budgets), 0));
DROP TABLE core_budgets_seq;
