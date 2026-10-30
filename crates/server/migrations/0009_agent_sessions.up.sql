-- Agent sessions (E2-08, P2.7): a harness on a runner, owned by the platform. Citadel's issue
-- runs become a client of it (E2-13). `secrets` holds the names and variables of what the
-- session is leased at each start, never a lease or a value. `state`: `starting` (not yet
-- confirmed by the runner), `running`, `interrupted` (its harness went with a runner restart;
-- the Core resumes it), `ended`, `lost` (its runner never came back for it).
CREATE TABLE core_agent_sessions (
    n               INTEGER PRIMARY KEY,
    id              TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 4 AND 64 AND id GLOB 'as_*'
                                AND substr(id, 4) NOT GLOB '*[^a-z0-9]*'),
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    runner          TEXT    NOT NULL REFERENCES core_devices(id),
    harness         TEXT    NOT NULL CHECK (length(harness) BETWEEN 1 AND 32),
    model           TEXT,
    prompt          TEXT,
    workspace       TEXT    CHECK (workspace IS NULL OR json_valid(workspace)),
    policy          TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(policy)),
    secrets         TEXT    NOT NULL DEFAULT '[]'
                            CHECK (json_valid(secrets) AND json_type(secrets) = 'array'),
    state           TEXT    NOT NULL
                            CHECK (state IN ('starting', 'running', 'interrupted', 'ended', 'lost')),
    harness_session TEXT,
    outcome         TEXT    CHECK (outcome IS NULL OR json_valid(outcome)),
    last_seq        INTEGER NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
    tokens_in       INTEGER NOT NULL DEFAULT 0,
    tokens_out      INTEGER NOT NULL DEFAULT 0,
    cache_read      INTEGER NOT NULL DEFAULT 0,
    cache_write     INTEGER NOT NULL DEFAULT 0,
    cost_usd_micros INTEGER,
    resumes         INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT    NOT NULL REFERENCES core_devices(id),
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    ended_at        TEXT
);

CREATE INDEX core_agent_sessions_live ON core_agent_sessions (state)
    WHERE state NOT IN ('ended', 'lost');

-- The transcript, as the runner numbered it (`seq` from 1, by one): each entry stored once,
-- whatever was resent, so a reader replays it from any `seq` with no gap.
CREATE TABLE core_agent_transcript (
    session TEXT    NOT NULL REFERENCES core_agent_sessions(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    seq     INTEGER NOT NULL CHECK (seq >= 1),
    at      INTEGER NOT NULL,
    body    TEXT    NOT NULL CHECK (json_valid(body)),
    PRIMARY KEY (session, seq)
) WITHOUT ROWID;
