-- What a session may do with connections (C4; design 2026-11-06-core-connections-design §4, §5). A row
-- is optional: a session with none acts as its creator's user, as the agent its own row names
-- (`core_agent_sessions.agent`), with no allowlist (every operation that user is granted). A row
-- narrows it: `allowlist` is the JSON array of capability names the session may call (NULL: none
-- named). An agent's session with no allowlist uses no connection tools (resolve refuses it).
-- Written by the Core, never by the runner or a call. `tc_seq` is the cursor over the runner's
-- numbered tool calls: advanced BEFORE a call runs, so a resent call never runs twice; the first
-- call of a session creates its row. Additive only.
CREATE TABLE core_session_connections (
    session   TEXT    PRIMARY KEY REFERENCES core_agent_sessions(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    allowlist TEXT    CHECK (allowlist IS NULL OR (json_valid(allowlist) AND json_type(allowlist) = 'array')),
    tc_seq    INTEGER NOT NULL DEFAULT 0 CHECK (tc_seq >= 0)
);
