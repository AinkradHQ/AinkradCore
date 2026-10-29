-- Several organisations (E15.14, pain #12): whether a company is the admin's own or a client's.
ALTER TABLE companies ADD COLUMN kind TEXT NOT NULL DEFAULT 'client'
    CHECK (kind IN ('own', 'client'));
