-- A project and its Brain room, strictly 1:1 (Projects plan D2, P1-03). The link lives here so the
-- Core never depends on the Brain: with the Brain off a project simply has no room. `project` is
-- core_projects.id as text, never a foreign key into the platform. Two UNIQUE paths: PRIMARY KEY
-- (project) and UNIQUE (room).
CREATE TABLE brain_project_rooms (
    project   TEXT PRIMARY KEY,
    room      TEXT NOT NULL UNIQUE REFERENCES brain_rooms(id),
    linked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
-- How far the `project.created` handler has read the event log (one row). A project that was
-- unlinked after its room was made is never linked again by a re-read.
CREATE TABLE brain_project_cursor (
    id  INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL
);
