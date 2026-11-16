-- Files attached to an AI session's messages (E4): kept with the session and shipped to its
-- runner with the message that names them (`agent.attach`). `pending` marks the ones of the
-- session's pending message (sent once its harness runs again). Removed with the session row, and
-- by the scheduler once the session has been over for the attachments' retention.
CREATE TABLE core_agent_attachments (
    id           TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 4 AND 64 AND id GLOB 'at_*'),
    session      TEXT    NOT NULL REFERENCES core_agent_sessions(id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name         TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    content_type TEXT    CHECK (content_type IS NULL OR length(content_type) <= 255),
    size         INTEGER NOT NULL CHECK (size >= 1),
    sha256       TEXT    NOT NULL CHECK (length(sha256) = 64),
    data         BLOB    NOT NULL,
    pending      INTEGER NOT NULL DEFAULT 0 CHECK (pending IN (0, 1)),
    created_by   TEXT    NOT NULL REFERENCES core_devices(id),
    created_at   TEXT    NOT NULL
);

CREATE INDEX core_agent_attachments_session ON core_agent_attachments (session);
