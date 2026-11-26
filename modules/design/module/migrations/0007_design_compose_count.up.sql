-- How many directions a compose asked for: 1 or 3 (the answer must match it).
ALTER TABLE design_composes ADD COLUMN count INTEGER NOT NULL DEFAULT 3 CHECK (count IN (1, 3));
