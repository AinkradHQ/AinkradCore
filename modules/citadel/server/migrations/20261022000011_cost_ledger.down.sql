DROP INDEX cost_events_price;
ALTER TABLE cost_events DROP COLUMN billing;
ALTER TABLE cost_events DROP COLUMN price_id;
DROP TABLE harness_billing;
DROP TABLE prices;
