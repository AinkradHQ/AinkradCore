-- Org integrity (E6.1, carried from E1.2/E1.3): the org and the issues pointing into it stay
-- within one company. A manager is in the agent's company and reporting lines have no cycle;
-- a team seat is held by an agent of the team's company; an issue's owner and next-actor
-- agents are in its project's company; departments, teams (across departments of different
-- companies) and agents never move to another company. `<>` against a missing row yields
-- NULL, so a dangling id falls through to its foreign key error instead.

CREATE TRIGGER agents_manager_insert BEFORE INSERT ON agents
WHEN NEW.reports_to IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'manager belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.reports_to) <> NEW.company_id;
    SELECT RAISE(ABORT, 'an agent cannot report to itself') WHERE NEW.reports_to = NEW.id;
END;

CREATE TRIGGER agents_manager_update BEFORE UPDATE OF reports_to ON agents
WHEN NEW.reports_to IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'manager belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.reports_to) <> NEW.company_id;
    SELECT RAISE(ABORT, 'reporting cycle')
    WHERE NEW.id IN (WITH RECURSIVE chain(id) AS (
        SELECT NEW.reports_to
        UNION SELECT a.reports_to FROM agents a JOIN chain c ON a.id = c.id
        WHERE a.reports_to IS NOT NULL) SELECT id FROM chain);
END;

CREATE TRIGGER agents_company_fixed BEFORE UPDATE OF company_id ON agents
WHEN NEW.company_id <> OLD.company_id
BEGIN
    SELECT RAISE(ABORT, 'an agent cannot move to another company');
END;

CREATE TRIGGER departments_company_fixed BEFORE UPDATE OF company_id ON departments
WHEN NEW.company_id <> OLD.company_id
BEGIN
    SELECT RAISE(ABORT, 'a department cannot move to another company');
END;

CREATE TRIGGER teams_company_fixed BEFORE UPDATE OF department_id ON teams
BEGIN
    SELECT RAISE(ABORT, 'a team cannot move to another company')
    WHERE (SELECT company_id FROM departments WHERE id = NEW.department_id)
       <> (SELECT company_id FROM departments WHERE id = OLD.department_id);
END;

CREATE TRIGGER team_memberships_same_company_insert BEFORE INSERT ON team_memberships
BEGIN
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.agent_id)
       <> (SELECT d.company_id FROM teams t JOIN departments d ON d.id = t.department_id
           WHERE t.id = NEW.team_id);
END;

CREATE TRIGGER team_memberships_same_company_update
BEFORE UPDATE OF team_id, agent_id ON team_memberships
BEGIN
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.agent_id)
       <> (SELECT d.company_id FROM teams t JOIN departments d ON d.id = t.department_id
           WHERE t.id = NEW.team_id);
END;

CREATE TRIGGER issues_agents_same_company_insert BEFORE INSERT ON issues
WHEN NEW.owner_agent_id IS NOT NULL OR NEW.next_agent_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'owner belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.owner_agent_id)
       <> (SELECT company_id FROM projects WHERE id = NEW.project_id);
    SELECT RAISE(ABORT, 'next actor belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.next_agent_id)
       <> (SELECT company_id FROM projects WHERE id = NEW.project_id);
END;

CREATE TRIGGER issues_agents_same_company_update
BEFORE UPDATE OF owner_agent_id, next_agent_id, project_id ON issues
WHEN NEW.owner_agent_id IS NOT NULL OR NEW.next_agent_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'owner belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.owner_agent_id)
       <> (SELECT company_id FROM projects WHERE id = NEW.project_id);
    SELECT RAISE(ABORT, 'next actor belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.next_agent_id)
       <> (SELECT company_id FROM projects WHERE id = NEW.project_id);
END;
