-- Live AI sessions (N41): one conversation, not one prompt. `live` 1: the harness stays up after an
-- answer and the session is `waiting` for the user; the stored `state` stays `running` (it holds its
-- slot and its supervisor), `waiting_since` (unix seconds) says it is idle and since when. `pending`
-- is a message for a session whose harness has to be started again (the supervisor delivers it once
-- the runner runs the session). `title` is a short name: the first message's first characters until
-- someone sets one. Additive only.
ALTER TABLE core_agent_sessions ADD COLUMN live INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_agent_sessions ADD COLUMN waiting_since INTEGER;
ALTER TABLE core_agent_sessions ADD COLUMN pending TEXT;
ALTER TABLE core_agent_sessions ADD COLUMN title TEXT;
