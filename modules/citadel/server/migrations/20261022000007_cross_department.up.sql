-- Escalation chain (E6.3, brainstorm §4): an issue flagged cross-department escalates past its
-- team's product owner to the company's CEO (or CTO without one) before the admin; any other
-- issue never climbs back through them. A request routed to several departments flags its
-- kickoff issues.
ALTER TABLE issues ADD COLUMN cross_department INTEGER NOT NULL DEFAULT 0
    CHECK (cross_department IN (0, 1));
