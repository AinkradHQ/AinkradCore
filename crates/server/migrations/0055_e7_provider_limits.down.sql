-- The `provider` kind stays allowed by the column CHECKs after a down (a rebuild would copy the tables
-- again). Provider budgets go (their spend and holds cascade). The ledger's provider subject rows are
-- insert-only and stay, harmless with no budget naming them.
DELETE FROM core_budgets WHERE subject_kind = 'provider';
