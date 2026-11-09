-- The requirement conversation hub (E15.11, pain #9, decisions #39, #44): one thread per
-- requirement (its intake issue's comments), where any agent working on the requirement asks the
-- admin (`ask_human`) and the answer goes back to the agent that asked, not the CEO.
--
-- A question is asked from an issue (the asker's), shown in the requirement's thread as a card
-- and in the issue's own thread as the agent's comment (`question_comment_id`). Answered in
-- either place, it is answered in both: the answer is the admin's comment on the asker's issue
-- (`answer_comment_id`), the asker is woken with it, and the card collapses to a receipt.
CREATE TABLE questions (
    id                  INTEGER PRIMARY KEY,
    -- NULL when the asker's issue serves no requirement: then only its own thread shows it.
    requirement_id      INTEGER REFERENCES requirements(id) ON DELETE CASCADE,
    issue_id            INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    agent_id            INTEGER NOT NULL REFERENCES agents(id),
    run_id              INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    question            TEXT    NOT NULL CHECK (question <> ''),
    options             TEXT    NOT NULL DEFAULT '[]'
                        CHECK (json_valid(options) AND json_type(options) = 'array'),
    state               TEXT    NOT NULL DEFAULT 'open'
                        CHECK (state IN ('open', 'answered', 'cancelled')),
    answer              TEXT,
    answered_by_user_id INTEGER REFERENCES users(id),
    -- Where it was answered: the requirement's thread or the asker's issue thread.
    answered_in         TEXT    CHECK (answered_in IN ('requirement', 'issue')),
    question_comment_id INTEGER REFERENCES comments(id) ON DELETE SET NULL,
    answer_comment_id   INTEGER REFERENCES comments(id) ON DELETE SET NULL,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    answered_at         TEXT,
    CHECK ((state = 'answered') = (answer IS NOT NULL AND answered_at IS NOT NULL))
);
CREATE INDEX questions_requirement ON questions (requirement_id, state);
CREATE INDEX questions_issue ON questions (issue_id, state);
CREATE INDEX questions_agent ON questions (agent_id);
