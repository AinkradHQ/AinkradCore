-- Work model: project → epic → story / task / bug → subtask (brainstorm §5).
-- Deleting a project removes its epics, sprints, labels, issues, links and comments.
-- Rows that point at another row of the same project are checked by triggers below.

CREATE TABLE projects (
    id                INTEGER PRIMARY KEY,
    user_id           INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id        INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    -- The owning team; the project survives the team.
    team_id           INTEGER REFERENCES teams(id) ON DELETE SET NULL,
    name              TEXT    NOT NULL,
    -- Issue-number prefix: CIT-12.
    key               TEXT    NOT NULL CHECK (key GLOB '[A-Z]*' AND key NOT GLOB '*[^A-Z0-9]*'),
    mode              TEXT    NOT NULL CHECK (mode IN ('scrum', 'kanban')),
    sprint_approval   TEXT    NOT NULL CHECK (sprint_approval IN ('owner', 'product_owner')),
    -- Next issue number; bumped in the same transaction that inserts the issue.
    next_issue_number INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (company_id, key)
);
CREATE INDEX projects_team ON projects (team_id);

CREATE TABLE epics (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'open'
               CHECK (status IN ('open', 'in_progress', 'done', 'cancelled')),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX epics_project ON epics (project_id);

CREATE TABLE sprints (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    goal       TEXT    NOT NULL DEFAULT '',
    state      TEXT    NOT NULL CHECK (state IN ('planned', 'active', 'closed')),
    starts_on  TEXT,
    ends_on    TEXT,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (starts_on IS NULL OR ends_on IS NULL OR ends_on >= starts_on)
);
CREATE INDEX sprints_project ON sprints (project_id);
-- At most one active sprint per project.
CREATE UNIQUE INDEX sprints_one_active ON sprints (project_id) WHERE state = 'active';

CREATE TABLE issues (
    id             INTEGER PRIMARY KEY,
    user_id        INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    number         INTEGER NOT NULL,
    epic_id        INTEGER REFERENCES epics(id) ON DELETE SET NULL,
    -- Subtasks go with their parent.
    parent_id      INTEGER REFERENCES issues(id) ON DELETE CASCADE,
    kind           TEXT    NOT NULL CHECK (kind IN ('story', 'task', 'bug', 'subtask')),
    title          TEXT    NOT NULL,
    body           TEXT    NOT NULL DEFAULT '',
    state          TEXT    NOT NULL CHECK (state IN
                   ('backlog', 'todo', 'in_progress', 'in_review', 'blocked', 'done', 'cancelled')),
    -- Owner: an agent or a human, or nobody.
    owner_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    owner_user_id  INTEGER REFERENCES users(id),
    -- Next actor (#4): exactly one of agent / human / timer, unless the issue is terminal.
    -- An agent that is someone's next actor cannot be deleted until the issue is reassigned.
    next_agent_id  INTEGER REFERENCES agents(id),
    next_user_id   INTEGER REFERENCES users(id),
    next_at        TEXT,
    points         INTEGER CHECK (points >= 0),
    sprint_id      INTEGER REFERENCES sprints(id) ON DELETE SET NULL,
    rank           REAL    NOT NULL,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (project_id, number),
    CHECK ((kind = 'subtask') = (parent_id IS NOT NULL)),
    CHECK (owner_agent_id IS NULL OR owner_user_id IS NULL),
    CHECK ((next_agent_id IS NOT NULL) + (next_user_id IS NOT NULL) + (next_at IS NOT NULL) <= 1),
    CHECK (state IN ('done', 'cancelled')
           OR next_agent_id IS NOT NULL OR next_user_id IS NOT NULL OR next_at IS NOT NULL)
);
CREATE INDEX issues_backlog ON issues (project_id, rank);
CREATE INDEX issues_epic ON issues (epic_id);
CREATE INDEX issues_parent ON issues (parent_id);
CREATE INDEX issues_sprint ON issues (sprint_id);
CREATE INDEX issues_owner_agent ON issues (owner_agent_id);
CREATE INDEX issues_next_agent ON issues (next_agent_id);

CREATE TABLE labels (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (project_id, name)
);

CREATE TABLE issue_labels (
    issue_id   INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label_id   INTEGER NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (issue_id, label_id)
);
CREATE INDEX issue_labels_label ON issue_labels (label_id);

-- `blocker` must close before `blocked` proceeds. Cycles are rejected by the store.
CREATE TABLE blocker_links (
    blocker_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (blocker_id, blocked_id),
    CHECK (blocker_id <> blocked_id)
);
CREATE INDEX blocker_links_blocked ON blocker_links (blocked_id);

CREATE TABLE comments (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    issue_id        INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    -- Author: exactly one of agent / human. Comments keep their author: an agent with
    -- comments cannot be deleted (terminate it instead).
    author_agent_id INTEGER REFERENCES agents(id),
    author_user_id  INTEGER REFERENCES users(id),
    body            TEXT    NOT NULL,
    -- Plain text until runs exist (E1.4).
    run_id          TEXT,
    idempotency_key TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((author_agent_id IS NULL) <> (author_user_id IS NULL)),
    UNIQUE (issue_id, idempotency_key)
);
CREATE INDEX comments_author_agent ON comments (author_agent_id);

-- Same-project / same-company rules. `<>` against a missing row yields NULL, so a dangling
-- id falls through to its foreign key error instead.

CREATE TRIGGER projects_team_same_company_insert BEFORE INSERT ON projects
WHEN NEW.team_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'team belongs to another company')
    WHERE (SELECT d.company_id FROM teams t JOIN departments d ON d.id = t.department_id
           WHERE t.id = NEW.team_id) <> NEW.company_id;
END;

CREATE TRIGGER projects_team_same_company_update BEFORE UPDATE OF team_id, company_id ON projects
WHEN NEW.team_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'team belongs to another company')
    WHERE (SELECT d.company_id FROM teams t JOIN departments d ON d.id = t.department_id
           WHERE t.id = NEW.team_id) <> NEW.company_id;
END;

CREATE TRIGGER issues_same_project_insert BEFORE INSERT ON issues
BEGIN
    SELECT RAISE(ABORT, 'epic belongs to another project')
    WHERE (SELECT project_id FROM epics WHERE id = NEW.epic_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'sprint belongs to another project')
    WHERE (SELECT project_id FROM sprints WHERE id = NEW.sprint_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'parent belongs to another project')
    WHERE (SELECT project_id FROM issues WHERE id = NEW.parent_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'a subtask cannot have subtasks')
    WHERE (SELECT kind FROM issues WHERE id = NEW.parent_id) = 'subtask';
END;

CREATE TRIGGER issues_same_project_update
BEFORE UPDATE OF project_id, epic_id, sprint_id, parent_id ON issues
BEGIN
    SELECT RAISE(ABORT, 'epic belongs to another project')
    WHERE (SELECT project_id FROM epics WHERE id = NEW.epic_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'sprint belongs to another project')
    WHERE (SELECT project_id FROM sprints WHERE id = NEW.sprint_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'parent belongs to another project')
    WHERE (SELECT project_id FROM issues WHERE id = NEW.parent_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'a subtask cannot have subtasks')
    WHERE (SELECT kind FROM issues WHERE id = NEW.parent_id) = 'subtask';
    SELECT RAISE(ABORT, 'an issue cannot be its own parent') WHERE NEW.parent_id = NEW.id;
    SELECT RAISE(ABORT, 'an issue with subtasks cannot become a subtask')
    WHERE NEW.parent_id IS NOT NULL AND EXISTS (SELECT 1 FROM issues WHERE parent_id = NEW.id);
END;

CREATE TRIGGER issue_labels_same_project BEFORE INSERT ON issue_labels
BEGIN
    SELECT RAISE(ABORT, 'label belongs to another project')
    WHERE (SELECT project_id FROM labels WHERE id = NEW.label_id)
       <> (SELECT project_id FROM issues WHERE id = NEW.issue_id);
END;
