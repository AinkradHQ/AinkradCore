-- Limits per provider (E7 closeout): a budget may name a `provider` (its id: `anthropic`, `openrouter`,
-- `claude-sub`) and then counts every account of that provider. `subject_kind` is a column CHECK on
-- `core_budgets` and on `core_cost_subjects`, so both are rebuilt (the pattern of 0046).
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
                    ('account', 'pool', 'provider', 'agent', 'company', 'department', 'project', 'sprint', 'issue')),
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
        usd_cap_micros, warn_at_percent, hard_stop, created_at, updated_at, message_cap)
    SELECT id, user_id, subject_kind, subject_id, company, period, token_cap, usd_cap_micros,
           warn_at_percent, hard_stop, created_at, updated_at, message_cap FROM core_budgets_bak;
INSERT INTO core_budget_spend (user_id, budget_id, period_key, tokens, usd_micros, raised,
        raised_usd_micros, warned_at, exhausted_at, messages)
    SELECT user_id, budget_id, period_key, tokens, usd_micros, raised, raised_usd_micros, warned_at,
           exhausted_at, messages FROM core_budget_spend_bak;
INSERT INTO core_budget_holds (id, user_id, session, budget_id, period_key, tokens, usd_micros,
        expires_at, created_at)
    SELECT id, user_id, session, budget_id, period_key, tokens, usd_micros, expires_at, created_at
    FROM core_budget_holds_bak;
DROP TABLE core_budget_holds_bak;
DROP TABLE core_budget_spend_bak;
DROP TABLE core_budgets_bak;

DELETE FROM sqlite_sequence WHERE name = 'core_budgets';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'core_budgets', max(coalesce((SELECT seq FROM core_budgets_seq), 0),
                               coalesce((SELECT max(id) FROM core_budgets), 0));
DROP TABLE core_budgets_seq;

-- The ledger's subject rows carry the same kind CHECK. Rebuilt with its index and insert-only triggers,
-- then every event of an account also counts against that account's provider.
CREATE TABLE core_cost_subjects_bak AS SELECT * FROM core_cost_subjects;
DROP TABLE core_cost_subjects;
CREATE TABLE core_cost_subjects (
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    event_id   INTEGER NOT NULL REFERENCES core_cost_events(id),
    kind       TEXT    NOT NULL CHECK (kind IN
               ('account', 'pool', 'provider', 'agent', 'company', 'department', 'project', 'sprint', 'issue')),
    subject_id TEXT    NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 64),
    PRIMARY KEY (event_id, kind, subject_id)
) WITHOUT ROWID;
CREATE INDEX core_cost_subjects_subject ON core_cost_subjects (kind, subject_id);
INSERT INTO core_cost_subjects (user_id, event_id, kind, subject_id)
    SELECT user_id, event_id, kind, subject_id FROM core_cost_subjects_bak;
DROP TABLE core_cost_subjects_bak;
CREATE TRIGGER core_cost_subjects_insert_only BEFORE UPDATE ON core_cost_subjects
BEGIN SELECT RAISE(ABORT, 'cost subjects are insert-only'); END;
CREATE TRIGGER core_cost_subjects_no_delete BEFORE DELETE ON core_cost_subjects
BEGIN SELECT RAISE(ABORT, 'cost subjects are insert-only'); END;
INSERT OR IGNORE INTO core_cost_subjects (user_id, event_id, kind, subject_id)
    SELECT s.user_id, s.event_id, 'provider', a.provider FROM core_cost_subjects s
    JOIN core_accounts a ON s.kind = 'account' AND CAST(a.id AS TEXT) = s.subject_id;
