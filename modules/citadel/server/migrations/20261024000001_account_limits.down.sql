ALTER TABLE accounts DROP COLUMN signal;
ALTER TABLE accounts DROP COLUMN status_until;
DROP INDEX account_events_window;
DROP TABLE account_events;
DROP TABLE account_limits;
