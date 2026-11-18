-- Design V6-01 round 3: how often the helper ran out of wall clock on an asset (`design_limit`), and when
-- a check last ran. Three timeouts refuse the asset; the pick goes by the last attempt so one file that
-- never finishes cannot hold the queue. Nothing here holds a secret.
ALTER TABLE design_assets ADD COLUMN check_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE design_assets ADD COLUMN check_tried_at TEXT;
