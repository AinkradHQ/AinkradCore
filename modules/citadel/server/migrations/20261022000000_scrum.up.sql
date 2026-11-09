-- Scrum (E5.2): what a sprint committed and completed, each member's capacity, and every
-- issue's state history, which the burndown (and E5.3's cycle and lead times) read.
--
-- The history is written by triggers, so no path that changes an issue's state (a
-- transition, a checkout, a raw write) can skip it; `at` is the database clock, like the
-- audit log's. It starts with this migration: issues already there have no rows.

-- Points in the sprint when it started, and done when it closed; NULL until then.
ALTER TABLE sprints ADD COLUMN committed_points INTEGER CHECK (committed_points >= 0);
ALTER TABLE sprints ADD COLUMN completed_points INTEGER CHECK (completed_points >= 0);

-- Story points the member can take on per sprint; NULL when not set.
ALTER TABLE team_memberships ADD COLUMN capacity INTEGER CHECK (capacity >= 0);

CREATE TABLE issue_state_history (
    id         INTEGER PRIMARY KEY,
    issue_id   INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    -- NULL for the state the issue was created in.
    from_state TEXT,
    to_state   TEXT    NOT NULL,
    at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX issue_state_history_issue ON issue_state_history (issue_id, at);

CREATE TRIGGER issues_history_insert AFTER INSERT ON issues
BEGIN
    INSERT INTO issue_state_history (issue_id, to_state, at)
    VALUES (NEW.id, NEW.state, NEW.created_at);
END;

CREATE TRIGGER issues_history_update AFTER UPDATE OF state ON issues
WHEN NEW.state <> OLD.state
BEGIN
    INSERT INTO issue_state_history (issue_id, from_state, to_state)
    VALUES (NEW.id, OLD.state, NEW.state);
END;
