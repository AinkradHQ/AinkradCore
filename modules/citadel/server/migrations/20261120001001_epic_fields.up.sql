-- Epic presentation and planning for the timeline (API minor 18): a colour (`#rrggbb`) and
-- start and end dates (`YYYY-MM-DD`), all optional. Its requirement already has a column.
ALTER TABLE epics ADD COLUMN color TEXT;
ALTER TABLE epics ADD COLUMN starts_on TEXT;
ALTER TABLE epics ADD COLUMN ends_on TEXT;
