-- Agent avatars (decision #61): an agent is shown as an animated figure the client draws, so
-- the server keeps only its appearance: the figure's version and one of the named palettes
-- below (their colours live in the client). A new agent is given the palette its company uses
-- least, ties broken by a rotation per company (`org::palette_pick!`): stable per agent,
-- spread evenly, and no two agents of a company share one while there are palettes to spare.
-- The admin may change it, and may upload an image that is shown instead of the figure
-- (`avatar_sha256`: stored content-addressed with the artifacts, at most `avatar.max_bytes`).
-- The palettes are the approved figure design's (Designs/citadel/figures/core.js), in its order;
-- the client's `muted` is for paused agents and is never assigned.
CREATE TABLE avatar_palettes (
    id       TEXT    PRIMARY KEY CHECK (id <> ''),
    name     TEXT    NOT NULL UNIQUE CHECK (name <> ''),
    position INTEGER NOT NULL UNIQUE CHECK (position > 0)
);
INSERT INTO avatar_palettes (position, id, name) VALUES
    (1, 'neon-tide', 'Neon Tide'), (2, 'aurora', 'Aurora'), (3, 'ultraviolet', 'Ultraviolet'),
    (4, 'glacier', 'Glacier'), (5, 'ember', 'Ember'), (6, 'orchid', 'Orchid'),
    (7, 'lagoon', 'Lagoon'), (8, 'citrine', 'Citrine'), (9, 'coral', 'Coral'), (10, 'jade', 'Jade'),
    (11, 'abyss', 'Abyss'), (12, 'dusk', 'Dusk'), (13, 'copper', 'Copper'),
    (14, 'lime-circuit', 'Lime Circuit'), (15, 'sakura', 'Sakura'), (16, 'cobalt', 'Cobalt'),
    (17, 'steel', 'Steel');
ALTER TABLE agents ADD COLUMN figure_version TEXT NOT NULL DEFAULT 'v1'
    CHECK (figure_version <> '');
ALTER TABLE agents ADD COLUMN palette_id TEXT NOT NULL DEFAULT 'neon-tide' CHECK (palette_id <> '');
ALTER TABLE agents ADD COLUMN avatar_sha256 TEXT
    CHECK (avatar_sha256 IS NULL OR length(avatar_sha256) = 64);
-- Existing agents: their place in their company, past the same rotation.
UPDATE agents SET palette_id = (SELECT p.id FROM avatar_palettes p WHERE p.position =
    ((SELECT count(*) FROM agents o WHERE o.company_id = agents.company_id AND o.id < agents.id)
     + agents.company_id * 7) % (SELECT count(*) FROM avatar_palettes) + 1);
