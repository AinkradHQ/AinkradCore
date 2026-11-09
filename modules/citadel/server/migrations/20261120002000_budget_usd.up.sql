-- Dollar budgets and the issue scope (parity API B2, item 1), and re-costing past runs (item 2).
--
-- A budget may carry `usd_cap_micros` (millionths of a dollar) beside its token cap: the same
-- period, the same warning and hard stop. A dollar cap with `token_cap = 0` is dollars only.
-- `budget_spend.usd_micros` counts the priced dollars of the period (an unpriced event adds
-- none); `raised_usd_micros` is what an approved `budget_overrun` added to the dollar cap.
-- A budget may also be on one issue. SQLite cannot change a CHECK in place, so budgets is
-- rebuilt, budget_spend and its trigger set aside first (as in 20261115000000).

DROP TRIGGER cost_events_budget_spend;
CREATE TABLE budget_spend_keep AS
    SELECT budget_id, period_key, tokens, raised, warned_at FROM budget_spend;
DROP TABLE budget_spend;

CREATE TABLE budgets_new (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    scope           TEXT    NOT NULL
                    CHECK (scope IN ('company', 'department', 'project', 'agent', 'sprint', 'issue')),
    company_id      INTEGER REFERENCES companies(id) ON DELETE CASCADE,
    department_id   INTEGER REFERENCES departments(id) ON DELETE CASCADE,
    project_id      INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    agent_id        INTEGER REFERENCES agents(id) ON DELETE CASCADE,
    sprint_id       INTEGER REFERENCES sprints(id) ON DELETE CASCADE,
    issue_id        INTEGER REFERENCES issues(id) ON DELETE CASCADE,
    scope_id        INTEGER GENERATED ALWAYS AS
                    (coalesce(company_id, department_id, project_id, agent_id, sprint_id,
                              issue_id)) VIRTUAL,
    period          TEXT    NOT NULL CHECK (period IN ('day', 'week', 'month', 'total')),
    token_cap       INTEGER NOT NULL CHECK (token_cap >= 0),
    usd_cap_micros  INTEGER CHECK (usd_cap_micros >= 0),
    warn_at_percent INTEGER NOT NULL DEFAULT 80 CHECK (warn_at_percent BETWEEN 1 AND 100),
    hard_stop       INTEGER NOT NULL DEFAULT 1 CHECK (hard_stop IN (0, 1)),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((company_id IS NOT NULL) = (scope = 'company')),
    CHECK ((department_id IS NOT NULL) = (scope = 'department')),
    CHECK ((project_id IS NOT NULL) = (scope = 'project')),
    CHECK ((agent_id IS NOT NULL) = (scope = 'agent')),
    CHECK ((sprint_id IS NOT NULL) = (scope = 'sprint')),
    CHECK ((issue_id IS NOT NULL) = (scope = 'issue')),
    UNIQUE (scope, scope_id, period)
);
INSERT INTO budgets_new (id, user_id, scope, company_id, department_id, project_id, agent_id,
    sprint_id, period, token_cap, warn_at_percent, hard_stop, created_at)
SELECT id, user_id, scope, company_id, department_id, project_id, agent_id, sprint_id, period,
       token_cap, warn_at_percent, hard_stop, created_at
FROM budgets;
DROP TABLE budgets;
ALTER TABLE budgets_new RENAME TO budgets;

CREATE TABLE budget_spend (
    budget_id         INTEGER NOT NULL REFERENCES budgets(id) ON DELETE CASCADE,
    period_key        TEXT    NOT NULL CHECK (period_key <> ''),
    tokens            INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    raised            INTEGER NOT NULL DEFAULT 0 CHECK (raised >= 0),
    warned_at         TEXT,
    usd_micros        INTEGER NOT NULL DEFAULT 0 CHECK (usd_micros >= 0),
    raised_usd_micros INTEGER NOT NULL DEFAULT 0 CHECK (raised_usd_micros >= 0),
    PRIMARY KEY (budget_id, period_key)
) WITHOUT ROWID;
INSERT INTO budget_spend (budget_id, period_key, tokens, raised, warned_at)
SELECT budget_id, period_key, tokens, raised, warned_at FROM budget_spend_keep;
DROP TABLE budget_spend_keep;

CREATE TRIGGER cost_events_budget_spend AFTER INSERT ON cost_events
BEGIN
    INSERT INTO budget_spend (budget_id, period_key, tokens, usd_micros)
    SELECT b.id, CASE b.period WHEN 'day' THEN date(NEW.created_at)
               WHEN 'week' THEN date(NEW.created_at, '-6 days', 'weekday 1')
               WHEN 'month' THEN strftime('%Y-%m', NEW.created_at) ELSE 'total' END,
           NEW.input_tokens + NEW.output_tokens + NEW.cache_tokens,
           coalesce(NEW.cost_usd_micros, 0)
    FROM budgets b
    WHERE b.agent_id = NEW.agent_id
       OR b.company_id = (SELECT company_id FROM agents WHERE id = NEW.agent_id)
       OR b.department_id IN (SELECT t.department_id FROM team_memberships m
           JOIN teams t ON t.id = m.team_id WHERE m.agent_id = NEW.agent_id)
       OR b.project_id = (SELECT project_id FROM issues WHERE id = NEW.issue_id)
       OR b.sprint_id = (SELECT sprint_id FROM issues WHERE id = NEW.issue_id)
       OR b.issue_id = NEW.issue_id
    ON CONFLICT (budget_id, period_key) DO UPDATE SET tokens = tokens + excluded.tokens,
        usd_micros = usd_micros + excluded.usd_micros;
END;

-- The dollars already in the ledger count toward the (existing, token-only) budgets' counters.
UPDATE budget_spend SET usd_micros = coalesce((
    SELECT sum(c.cost_usd_micros) FROM budgets b JOIN cost_events c
        ON b.agent_id = c.agent_id
        OR b.company_id = (SELECT company_id FROM agents WHERE id = c.agent_id)
        OR b.department_id IN (SELECT t.department_id FROM team_memberships m
            JOIN teams t ON t.id = m.team_id WHERE m.agent_id = c.agent_id)
        OR b.project_id = (SELECT project_id FROM issues WHERE id = c.issue_id)
        OR b.sprint_id = (SELECT sprint_id FROM issues WHERE id = c.issue_id)
        OR b.issue_id = c.issue_id
    WHERE b.id = budget_spend.budget_id
      AND CASE b.period WHEN 'day' THEN date(c.created_at)
           WHEN 'week' THEN date(c.created_at, '-6 days', 'weekday 1')
           WHEN 'month' THEN strftime('%Y-%m', c.created_at) ELSE 'total' END
          = budget_spend.period_key), 0);

-- Item 2: re-costing past runs fills in the dollars of an event that had none (never one that
-- has them), so the insert-only trigger now lets exactly that update through.
DROP TRIGGER cost_events_insert_only;
CREATE TRIGGER cost_events_insert_only
BEFORE UPDATE OF id, user_id, run_id, agent_id, input_tokens, output_tokens, cache_tokens,
    cost_usd_micros, priced, idempotency_key, created_at ON cost_events
WHEN OLD.priced = 1 OR NEW.priced = 0 OR NEW.id IS NOT OLD.id OR NEW.user_id IS NOT OLD.user_id
    OR NEW.run_id IS NOT OLD.run_id OR NEW.agent_id IS NOT OLD.agent_id
    OR NEW.input_tokens IS NOT OLD.input_tokens OR NEW.output_tokens IS NOT OLD.output_tokens
    OR NEW.cache_tokens IS NOT OLD.cache_tokens
    OR NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'cost events are insert-only');
END;
