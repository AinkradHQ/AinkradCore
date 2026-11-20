-- A row still waiting out its Undo window is gone to every reader already: it is removed for good.
DELETE FROM core_accounts WHERE deleted_at IS NOT NULL;
DROP TABLE core_account_wipes;
DROP INDEX core_accounts_deleted;
ALTER TABLE core_accounts DROP COLUMN deleted_seats;
ALTER TABLE core_accounts DROP COLUMN deleted_prev;
ALTER TABLE core_accounts DROP COLUMN deleted_at;
