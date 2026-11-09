-- What the owning module calls a session it drives (E2-13, S8): a non-secret pointer (`run:12`)
-- so a session that is started again (a resume after a restart) finds its run and gets a fresh
-- credential. Never a credential itself. NULL for a client's session.
ALTER TABLE core_agent_sessions ADD COLUMN owner_ref TEXT
    CHECK (owner_ref IS NULL OR length(owner_ref) BETWEEN 1 AND 64);
