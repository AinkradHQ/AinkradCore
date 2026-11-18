-- B7-02 fix: the distil run that made each citation, so the me card can tell "two sessions in two
-- runs" from "one answer". Old rows take the run that created their record (a reinforcement's own
-- run is not recorded for them, so they undercount, never overcount). Nullable: a NULL run counts
-- for nothing.
ALTER TABLE record_sources ADD COLUMN run TEXT;
UPDATE record_sources SET run = (SELECT distil FROM records WHERE records.id = record_sources.record);
