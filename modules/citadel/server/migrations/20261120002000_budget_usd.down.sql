DROP TRIGGER cost_events_insert_only;
CREATE TRIGGER cost_events_insert_only
BEFORE UPDATE OF id, user_id, run_id, agent_id, input_tokens, output_tokens, cache_tokens,
    cost_usd_micros, priced, idempotency_key, created_at ON cost_events
BEGIN
    SELECT RAISE(ABORT, 'cost events are insert-only');
END;

DROP TRIGGER cost_events_budget_spend;
CREATE TABLE budget_spend_keep AS
    SELECT budget_id, period_key, tokens, raised, warned_at FROM budget_spend
    WHERE budget_id IN (SELECT id FROM budgets WHERE scope <> 'issue');
DROP TABLE budget_spend;

CREATE TABLE budgets_old (
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
INSERT INTO budgets_old (id, user_id, scope, company_id, department_id, project_id, agent_id,
    sprint_id, period, token_cap, warn_at_percent, hard_stop, created_at)
SELECT id, user_id, scope, company_id, department_id, project_id, agent_id, sprint_id, period,
       token_cap, warn_at_percent, hard_stop, created_at
FROM budgets WHERE scope <> 'issue';
DROP TABLE budgets;
ALTER TABLE budgets_old RENAME TO budgets;

CREATE TABLE budget_spend (
    budget_id  INTEGER NOT NULL REFERENCES budgets(id) ON DELETE CASCADE,
    period_key TEXT    NOT NULL CHECK (period_key <> ''),
    tokens     INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    raised     INTEGER NOT NULL DEFAULT 0 CHECK (raised >= 0),
    warned_at  TEXT,
    PRIMARY KEY (budget_id, period_key)
) WITHOUT ROWID;
INSERT INTO budget_spend (budget_id, period_key, tokens, raised, warned_at)
SELECT budget_id, period_key, tokens, raised, warned_at FROM budget_spend_keep;
DROP TABLE budget_spend_keep;

CREATE TRIGGER cost_events_budget_spend AFTER INSERT ON cost_events
BEGIN
    INSERT INTO budget_spend (budget_id, period_key, tokens)
    SELECT b.id, CASE b.period WHEN 'day' THEN date(NEW.created_at)
               WHEN 'week' THEN date(NEW.created_at, '-6 days', 'weekday 1')
               WHEN 'month' THEN strftime('%Y-%m', NEW.created_at) ELSE 'total' END,
           NEW.input_tokens + NEW.output_tokens + NEW.cache_tokens
    FROM budgets b
    WHERE b.agent_id = NEW.agent_id
       OR b.company_id = (SELECT company_id FROM agents WHERE id = NEW.agent_id)
       OR b.department_id IN (SELECT t.department_id FROM team_memberships m
           JOIN teams t ON t.id = m.team_id WHERE m.agent_id = NEW.agent_id)
       OR b.project_id = (SELECT project_id FROM issues WHERE id = NEW.issue_id)
       OR b.sprint_id = (SELECT sprint_id FROM issues WHERE id = NEW.issue_id)
    ON CONFLICT (budget_id, period_key) DO UPDATE SET tokens = tokens + excluded.tokens;
END;
