-- What a session may do with connections (C4; design 2026-11-06-core-connections-design §4, §5). One
-- row per session that is given connection tools; a session with no row has none (deny by default).
-- `agent` is the agent id whose connection grants narrow the user's (NULL: the user's own grants only,
-- and then `allowlist` is still required); `allowlist` is the JSON array of capability names the session may
-- call. Written by the Core when the session is made, never by the runner or a call. `tc_seq` is the
-- cursor over the runner's numbered tool calls: advanced BEFORE a call runs, so a resent call never runs
-- twice. Additive only.
CREATE TABLE core_session_connections (
    session   TEXT    PRIMARY KEY REFERENCES core_agent_sessions(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    agent     TEXT    CHECK (agent IS NULL OR length(agent) BETWEEN 1 AND 64),
    allowlist TEXT    NOT NULL CHECK (json_valid(allowlist) AND json_type(allowlist) = 'array'),
    tc_seq    INTEGER NOT NULL DEFAULT 0 CHECK (tc_seq >= 0)
);
