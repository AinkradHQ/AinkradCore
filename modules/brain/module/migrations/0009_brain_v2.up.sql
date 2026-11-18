-- Brain v2 control plane (B2-01). Ids, counts and settings only; no content lands here.
ALTER TABLE brain_distils ADD COLUMN "trigger" TEXT NOT NULL DEFAULT 'manual'
    CHECK ("trigger" IN ('manual','session_end','threshold','checkpoint','hook','redistil','tidy','judge'));
ALTER TABLE brain_distils ADD COLUMN of_session TEXT;
-- NULL = keep forever.
ALTER TABLE brain_room_policy ADD COLUMN retention_days INTEGER CHECK (retention_days IS NULL OR retention_days >= 1);
ALTER TABLE brain_room_policy ADD COLUMN daily_distils INTEGER NOT NULL DEFAULT 12 CHECK (daily_distils BETWEEN 0 AND 1000);
-- Auto-save is the default (Ahmed, 2026-11-18): rooms that saved nothing automatically now save every
-- kind, with Undo. A room is set back to review by writing `[]` afterwards; a room that chose `[]`
-- before this cannot be told from one that never chose, and is switched too (plan D-default).
UPDATE brain_room_policy
    SET auto_accept = '["decision","fact","preference","project-state","rule","summary","task"]'
    WHERE auto_accept = '[]';
-- What one session was already given, so a prompt hook never repeats a record. Ids only.
CREATE TABLE brain_session_loaded (
    session TEXT NOT NULL,
    room    TEXT NOT NULL REFERENCES brain_rooms(id),
    record  TEXT NOT NULL,
    PRIMARY KEY (session, record)
);
-- How far the `agent.session.ended` handler has read the event log (one row), like brain_project_cursor.
CREATE TABLE brain_session_cursor (
    id  INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL
);
