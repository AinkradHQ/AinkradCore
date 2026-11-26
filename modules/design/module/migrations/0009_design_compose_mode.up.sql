-- What a compose draws: `screens` (frames, the default) or `system` (the tokens of a design-system doc).
ALTER TABLE design_composes ADD COLUMN mode TEXT NOT NULL DEFAULT 'screens' CHECK (mode IN ('screens', 'system'));
