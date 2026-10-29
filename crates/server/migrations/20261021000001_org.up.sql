-- Org model: company → departments → teams → agents (brainstorm §4).
-- Deleting a company removes its departments, teams, agents and memberships.

CREATE TABLE companies (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Free-form departments (#17), unique by name within a company.
CREATE TABLE departments (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (company_id, name)
);

CREATE TABLE teams (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX teams_department ON teams (department_id);

CREATE TABLE agents (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id  INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    role        TEXT    NOT NULL,
    org_role    TEXT    NOT NULL DEFAULT 'none' CHECK (org_role IN ('ceo', 'cto', 'none')),
    -- A manager leaving does not delete their reports; they become unattached.
    reports_to  INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    harness     TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model       TEXT    NOT NULL,
    runner_tags TEXT    NOT NULL DEFAULT '[]'
                CHECK (json_valid(runner_tags) AND json_type(runner_tags) = 'array'),
    status      TEXT    NOT NULL
                CHECK (status IN ('active', 'paused', 'pending_approval', 'terminated')),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX agents_company ON agents (company_id);
CREATE INDEX agents_reports_to ON agents (reports_to);
-- At most one CEO and one CTO per company.
CREATE UNIQUE INDEX agents_one_per_org_role ON agents (company_id, org_role)
    WHERE org_role <> 'none';

CREATE TABLE team_memberships (
    team_id    INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    agent_id   INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    team_role  TEXT    NOT NULL CHECK (team_role IN ('product_owner', 'team_lead', 'member')),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (team_id, agent_id)
);
CREATE INDEX team_memberships_agent ON team_memberships (agent_id);
-- At most one product owner and one team lead per team.
CREATE UNIQUE INDEX team_memberships_one_per_lead_role ON team_memberships (team_id, team_role)
    WHERE team_role <> 'member';
