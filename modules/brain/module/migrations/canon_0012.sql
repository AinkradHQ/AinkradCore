-- Brain redesign (API minor 101): a rule the person stopped following stays and is shown, but AI sessions are not given it.
ALTER TABLE records ADD COLUMN following INTEGER NOT NULL DEFAULT 1;
