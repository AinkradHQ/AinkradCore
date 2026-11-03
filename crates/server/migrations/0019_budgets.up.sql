-- The Core budget engine (KAN-448, design 2026-11-02-ai-provider-accounts §7, §11b item 3, §12d): limits per
-- subject over a calendar period, a warning and a hard stop, mid-run enforcement and an atomic reserve for
-- a new session. Moved here from Citadel's E7.2 (`citadel_budgets`, `citadel_budget_spend`); Citadel keeps
-- agents, companies, projects and work and asks the Core. A subject is OPAQUE TEXT (like
-- `core_pool_bindings.agent`): Core has no foreign key into any module, so a module deletes its own
-- subject's budgets through `store::budgets::remove`, not by cascade.
--
-- `company` is the subject's company binding, set by whoever writes the budget: a budget route can be
-- filtered by it (KAN-294), and for a company budget it is the subject itself.

CREATE TABLE core_budgets (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    subject_kind    TEXT    NOT NULL CHECK (subject_kind IN
                    ('account', 'pool', 'agent', 'company', 'department', 'project', 'sprint', 'issue')),
    subject_id      TEXT    NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 64),
    company         TEXT    CHECK (company IS NULL OR length(company) BETWEEN 1 AND 64),
    period          TEXT    NOT NULL CHECK (period IN ('day', 'week', 'month', 'total')),
    token_cap       INTEGER NOT NULL CHECK (token_cap >= 0),
    usd_cap_micros  INTEGER CHECK (usd_cap_micros >= 0),
    warn_at_percent INTEGER NOT NULL DEFAULT 80 CHECK (warn_at_percent BETWEEN 1 AND 100),
    hard_stop       INTEGER NOT NULL DEFAULT 1 CHECK (hard_stop IN (0, 1)),
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    CHECK (subject_kind <> 'company' OR company = subject_id),
    UNIQUE (subject_kind, subject_id, period)
);

CREATE INDEX core_budgets_company ON core_budgets (company) WHERE company IS NOT NULL;

-- What a budget has used in one period (`period_key`: `2026-10-22`, a week's Monday, `2026-10` or `total`),
-- moved by `store::budgets::apply_in` in the transaction that records the cost event, so admission and the
-- mid-run check read one row and never sum the ledger. `raised` is what approved overruns added.
-- `usd_micros` has no lower bound: a billing correction may lower it, in the period of the event it corrects.
CREATE TABLE core_budget_spend (
    budget_id         INTEGER NOT NULL REFERENCES core_budgets(id) ON DELETE CASCADE,
    period_key        TEXT    NOT NULL CHECK (period_key <> ''),
    tokens            INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    usd_micros        INTEGER NOT NULL DEFAULT 0,
    raised            INTEGER NOT NULL DEFAULT 0 CHECK (raised >= 0),
    raised_usd_micros INTEGER NOT NULL DEFAULT 0 CHECK (raised_usd_micros >= 0),
    warned_at         TEXT,
    exhausted_at      TEXT,
    PRIMARY KEY (budget_id, period_key)
) WITHOUT ROWID;

-- A reservation: what a new session may still spend, held against each hard-stop budget that applies to
-- it, in the same write transaction that checked the headroom (so two sessions cannot both take the last
-- of it). A hold shrinks as the session's cost is recorded, is dropped when the session ends, and lapses
-- at `expires_at` if nobody releases it (a session that died).
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
