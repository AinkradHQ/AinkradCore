-- Runner admin (1.20): a drained runner takes no new run (its runs finish); the admin's Power
-- Nap preference for it (pushed to it); its state as it last reported it (`RunnerInfo`: slots,
-- uptime, logins, last sleep) with when, and the harness versions of its last `Hello`.
ALTER TABLE runners ADD COLUMN drained_at TEXT;
ALTER TABLE runners ADD COLUMN power_nap INTEGER CHECK (power_nap IS NULL OR power_nap IN (0, 1));
ALTER TABLE runners ADD COLUMN info TEXT CHECK (info IS NULL OR json_valid(info));
ALTER TABLE runners ADD COLUMN info_at TEXT;
ALTER TABLE runners ADD COLUMN harnesses TEXT CHECK (harnesses IS NULL OR json_valid(harnesses));
