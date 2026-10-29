-- apply_plan (E15.18, decision #59): a whole plan filed in one call is idempotent by its client
-- key. The first result is kept per requirement and key, and a repeat returns it, filing nothing.
CREATE TABLE plan_applies (
    id             INTEGER PRIMARY KEY,
    requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
    client_key     TEXT    NOT NULL CHECK (client_key <> '' AND length(client_key) <= 200),
    agent_id       INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    result         TEXT    NOT NULL,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (requirement_id, client_key)
);
