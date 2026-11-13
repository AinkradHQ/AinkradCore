-- Who besides the matching project may see a room through Code Mode (plan D3, E4.1): a `project`
-- key, a `runner` id or a `session` id. No row at all means "project match only". Module-only
-- table; values are text, never foreign keys into the platform.
CREATE TABLE brain_room_access (
    room  TEXT NOT NULL REFERENCES brain_rooms(id),
    kind  TEXT NOT NULL CHECK (kind IN ('project','runner','session')),
    value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 200),
    PRIMARY KEY (room, kind, value)
);
