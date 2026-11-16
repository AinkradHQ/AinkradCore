-- Where a running Overview write is (API minor 80): `stage`, when it began, and how many items the
-- local model picked. All NULL when nothing is being written.
ALTER TABLE room_overview ADD COLUMN stage TEXT;
ALTER TABLE room_overview ADD COLUMN stage_since TEXT;
ALTER TABLE room_overview ADD COLUMN picked INTEGER;
