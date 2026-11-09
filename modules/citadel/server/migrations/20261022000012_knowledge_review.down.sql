-- Back to one human decider and no target or reason. A lead's decision is kept as the
-- admin's (user 1), the only decider the old shape can hold; a spec proposal stays a plain
-- `state` entry.

CREATE TABLE sprint_retro_items_keep AS SELECT entry_id, sprint_id FROM sprint_retro_items;
DROP TABLE sprint_retro_items;

CREATE TABLE knowledge_entries_old (
    id                   INTEGER PRIMARY KEY,
    user_id              INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id           INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind                 TEXT    NOT NULL CHECK (kind IN ('decision', 'landmine', 'state', 'retro')),
    title                TEXT    NOT NULL,
    body                 TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'proposed'
                         CHECK (status IN ('proposed', 'accepted', 'rejected')),
    proposed_by_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    decided_by_user_id   INTEGER REFERENCES users(id),
    created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((status = 'proposed') = (decided_by_user_id IS NULL))
);
INSERT INTO knowledge_entries_old (id, user_id, project_id, kind, title, body, status,
    proposed_by_agent_id, decided_by_user_id, created_at)
SELECT id, user_id, project_id, kind, title, body, status, proposed_by_agent_id,
       CASE WHEN decided_by_agent_id IS NOT NULL THEN 1 ELSE decided_by_user_id END, created_at
FROM knowledge_entries;
DROP TABLE knowledge_entries;
ALTER TABLE knowledge_entries_old RENAME TO knowledge_entries;
CREATE INDEX knowledge_entries_project ON knowledge_entries (project_id, status);
CREATE INDEX knowledge_entries_proposed_by ON knowledge_entries (proposed_by_agent_id);
CREATE TRIGGER knowledge_entries_same_company BEFORE INSERT ON knowledge_entries
BEGIN
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM agents WHERE id = NEW.proposed_by_agent_id)
       <> (SELECT company_id FROM projects WHERE id = NEW.project_id);
END;

CREATE TABLE sprint_retro_items (
    entry_id  INTEGER PRIMARY KEY REFERENCES knowledge_entries(id) ON DELETE CASCADE,
    sprint_id INTEGER NOT NULL REFERENCES sprints(id) ON DELETE CASCADE
);
CREATE INDEX sprint_retro_items_sprint ON sprint_retro_items (sprint_id);
CREATE TRIGGER sprint_retro_items_same_project BEFORE INSERT ON sprint_retro_items
BEGIN
    SELECT RAISE(ABORT, 'sprint belongs to another project')
    WHERE (SELECT project_id FROM sprints WHERE id = NEW.sprint_id)
       <> (SELECT project_id FROM knowledge_entries WHERE id = NEW.entry_id);
END;
INSERT INTO sprint_retro_items (entry_id, sprint_id)
SELECT entry_id, sprint_id FROM sprint_retro_items_keep;
DROP TABLE sprint_retro_items_keep;
