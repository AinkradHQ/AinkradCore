-- Brain control plane (plan §4.2): ids, names, policy and rules only. No content ever lands here;
-- items live in encrypted staging and room files.
CREATE TABLE brain_rooms (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind        TEXT NOT NULL CHECK (kind IN ('personal','product','employer','client','general','global-safe')),
    state       TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','archived')),
    review_days INTEGER NOT NULL DEFAULT 90 CHECK (review_days BETWEEN 1 AND 3650),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE brain_room_policy (
    room              TEXT PRIMARY KEY REFERENCES brain_rooms(id),
    allowed_providers TEXT NOT NULL DEFAULT '["approved_cloud"]',
    auto_accept       TEXT NOT NULL DEFAULT '[]',
    lease_hours       INTEGER NOT NULL DEFAULT 24 CHECK (lease_hours BETWEEN 1 AND 168)
);
CREATE TABLE brain_device_rooms (
    device TEXT NOT NULL,
    room   TEXT NOT NULL REFERENCES brain_rooms(id),
    rights TEXT NOT NULL CHECK (rights IN ('read','write')),
    PRIMARY KEY (device, room)
);
CREATE TABLE brain_sources (
    id       TEXT PRIMARY KEY,
    device   TEXT NOT NULL,
    kind     TEXT NOT NULL,
    enabled  INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    roots    TEXT NOT NULL DEFAULT '[]',
    cursor   TEXT NOT NULL DEFAULT '{}',
    last_run TEXT
);
CREATE TABLE brain_import_runs (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL CHECK (kind IN ('full','incremental')),
    state        TEXT NOT NULL CHECK (state IN ('collecting','discovering','review','committing','committed','abandoned')),
    stage        TEXT NOT NULL DEFAULT 'collect',
    counts       TEXT NOT NULL DEFAULT '{}',
    sources      TEXT NOT NULL DEFAULT '[]',
    done         TEXT NOT NULL DEFAULT '[]',
    started_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    committed_at TEXT
);
CREATE TABLE brain_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL CHECK (kind IN ('project','path','org','tracker','source','item_hash')),
    pattern    TEXT NOT NULL CHECK (length(pattern) BETWEEN 1 AND 500),
    action     TEXT NOT NULL CHECK (action IN ('refuse','route_to_room')),
    room       TEXT,
    origin     TEXT NOT NULL CHECK (origin IN ('seed','user')),
    locked     INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0,1)),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (kind, pattern, action)
);
-- A hash, never text: dedupe across runs. `room` is a room id or the word `refused`.
CREATE TABLE brain_seen (
    content_hash TEXT NOT NULL,
    room         TEXT NOT NULL,
    run          TEXT NOT NULL,
    PRIMARY KEY (content_hash, room)
);
INSERT INTO brain_rules (kind, pattern, action, origin, locked, reason) VALUES
    ('project', 'GitScope', 'refuse', 'seed', 1, 'Deprecated project'),
    ('project', 'Finvo',    'refuse', 'seed', 1, 'Deprecated project'),
    ('project', 'Habtic',   'refuse', 'seed', 1, 'Deprecated project'),
    ('project', 'ILINK',    'refuse', 'seed', 1, 'Deprecated project'),
    ('project', 'JoseOs',   'refuse', 'seed', 1, 'Deprecated project');
