-- What a run created through its MCP token, by kind (issues, approvals, comments, knowledge
-- entries, repo requests, questions, artifacts). A tool reserves its amount in the one statement
-- that checks the cap, so parallel calls cannot overshoot it.
CREATE TABLE citadel_run_creations (
    run_id INTEGER NOT NULL REFERENCES citadel_runs (id) ON DELETE CASCADE,
    kind   TEXT    NOT NULL,
    n      INTEGER NOT NULL CHECK (n >= 0),
    PRIMARY KEY (run_id, kind)
) WITHOUT ROWID;
