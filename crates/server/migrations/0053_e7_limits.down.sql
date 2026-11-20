-- The `hour5` period stays allowed by the column CHECK after a down (a rebuild would copy every table
-- again); its budgets and the message counters go.
DELETE FROM core_budgets WHERE period = 'hour5';
ALTER TABLE core_budget_spend DROP COLUMN messages;
ALTER TABLE core_budgets DROP COLUMN message_cap;
