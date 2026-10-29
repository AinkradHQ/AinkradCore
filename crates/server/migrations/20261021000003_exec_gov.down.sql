-- comments.run_id goes back to plain text, keeping the ids.
CREATE TABLE comments_old (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    issue_id        INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
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
INSERT INTO comments_old
    (id, user_id, issue_id, author_agent_id, author_user_id, body, run_id, idempotency_key,
     created_at)
SELECT id, user_id, issue_id, author_agent_id, author_user_id, body, CAST(run_id AS TEXT),
       idempotency_key, created_at
FROM comments;
DROP TABLE comments;
ALTER TABLE comments_old RENAME TO comments;
CREATE INDEX comments_author_agent ON comments (author_agent_id);

DROP TABLE device_keys;
DROP TABLE knowledge_entries;
DROP TABLE skills;
DROP TABLE budgets;
DROP TABLE approvals;
DROP TABLE cost_events;
DROP TABLE leases;
DROP TABLE runs;
DROP TABLE wake_requests;
DROP TABLE runners;
