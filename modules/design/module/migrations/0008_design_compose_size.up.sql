-- The screen size a compose draws at, in points: 360 x 630 (a phone) unless the request said otherwise.
ALTER TABLE design_composes ADD COLUMN w REAL NOT NULL DEFAULT 360;
ALTER TABLE design_composes ADD COLUMN h REAL NOT NULL DEFAULT 630;
