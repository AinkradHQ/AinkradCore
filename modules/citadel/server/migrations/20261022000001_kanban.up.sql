-- Kanban (E5.3): the most top-level issues a column (an open state) of a kanban project may
-- hold. The engine refuses a transition into a full column; a scrum project's limits, if
-- its mode changed, are ignored.
CREATE TABLE wip_limits (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    state      TEXT    NOT NULL
               CHECK (state IN ('backlog', 'todo', 'in_progress', 'in_review', 'blocked')),
    max_issues INTEGER NOT NULL CHECK (max_issues > 0),
    PRIMARY KEY (project_id, state)
);
