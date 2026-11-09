-- How the admin wants a sleeping runner back (decision #35): `now` ("Wake my Mac", pushed) or
-- `when_back` ("Run when I'm back"); set with `wake_requested_at`, cleared when it connects.
ALTER TABLE runners ADD COLUMN wake_mode TEXT CHECK (wake_mode IN ('now', 'when_back'));
