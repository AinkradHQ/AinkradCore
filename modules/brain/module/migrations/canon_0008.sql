-- B4-02 review: a saved record whose `replaces` lacked the evidence to retire its target names that
-- target here instead; both stay in force until room tidy (B9-01) reconciles them. Nullable, so it
-- is safe on a room file that already holds records.
ALTER TABLE records ADD COLUMN contests TEXT;
