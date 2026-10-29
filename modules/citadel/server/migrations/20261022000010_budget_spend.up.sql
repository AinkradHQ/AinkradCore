-- Running spend per budget and period (E7.2), so admission and the mid-run cap read one row
-- per budget instead of summing the ledger on every dispatch (Paperclip's mistake).
--
-- Periods are calendar periods in UTC, keyed by when the cost event was recorded: a day
-- (`2026-10-22`), a week (its Monday, `2026-10-19`), a month (`2026-10`), or `total`. A cost
-- event counts toward every budget that applies to it when it is recorded: its agent's, the
-- agent's company's, the departments the agent sits in through its teams, and its issue's
-- project's and sprint's. The trigger below keeps the counters in the cost event's own
-- transaction, whoever writes it; `ainkrad-core-server budget recompute` rebuilds them from the
-- ledger (as the org stands then) if they ever drift.
--
-- `raised`: tokens added for this period by approved `budget_overrun` approvals.
-- `warned_at`: when this period's warning (at `warn_at_percent`) went out; once per period.
CREATE TABLE budget_spend (
    budget_id  INTEGER NOT NULL REFERENCES budgets(id) ON DELETE CASCADE,
    period_key TEXT    NOT NULL CHECK (period_key <> ''),
    tokens     INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    raised     INTEGER NOT NULL DEFAULT 0 CHECK (raised >= 0),
    warned_at  TEXT,
    PRIMARY KEY (budget_id, period_key)
) WITHOUT ROWID;

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

-- The spend already in the ledger.
INSERT INTO budget_spend (budget_id, period_key, tokens)
SELECT b.id, CASE b.period WHEN 'day' THEN date(c.created_at)
           WHEN 'week' THEN date(c.created_at, '-6 days', 'weekday 1')
           WHEN 'month' THEN strftime('%Y-%m', c.created_at) ELSE 'total' END AS period_key,
       sum(c.input_tokens + c.output_tokens + c.cache_tokens)
FROM budgets b JOIN cost_events c
    ON b.agent_id = c.agent_id
    OR b.company_id = (SELECT company_id FROM agents WHERE id = c.agent_id)
    OR b.department_id IN (SELECT t.department_id FROM team_memberships m
        JOIN teams t ON t.id = m.team_id WHERE m.agent_id = c.agent_id)
    OR b.project_id = (SELECT project_id FROM issues WHERE id = c.issue_id)
    OR b.sprint_id = (SELECT sprint_id FROM issues WHERE id = c.issue_id)
WHERE true
GROUP BY b.id, period_key;
