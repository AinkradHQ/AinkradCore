-- CEO intake (E6.2, decision #11): each company has at most one intake project, created on
-- the first request. Its issues are requests for new goals or projects, waiting on the CEO
-- (or the admin when there is none) to route them to departments; it has no team.
ALTER TABLE projects ADD COLUMN intake INTEGER NOT NULL DEFAULT 0 CHECK (intake IN (0, 1));
CREATE UNIQUE INDEX projects_one_intake ON projects (company_id) WHERE intake = 1;
