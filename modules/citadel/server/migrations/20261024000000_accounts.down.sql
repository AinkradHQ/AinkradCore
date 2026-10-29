DROP TRIGGER runs_account_company;
DROP INDEX cost_events_account;
ALTER TABLE cost_events DROP COLUMN account_id;
DROP INDEX runs_account;
ALTER TABLE runs DROP COLUMN account_id;
DROP TABLE account_companies;
DROP TABLE accounts;
