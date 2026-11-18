-- Design V4-01: the asset library (T8). Content-addressed: the sha256 of the stored bytes is the key, so
-- the same upload is the same row. Bytes live in the database (the attachments pattern) and share its
-- backup. The API sanitises SVG and sniffs every type before a row exists; fonts and Icon Composer zips
-- are stored inert (`check_state = 'pending'`) until the helper parses them (V6-01): the Core never does.
-- Nothing here holds a secret.

CREATE TABLE design_assets (
    sha256       TEXT PRIMARY KEY CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    kind         TEXT NOT NULL CHECK (kind IN ('image', 'icon', 'logo', 'icon_composer', 'font', 'pdf', 'mockup_file', 'shot')),
    name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200 AND name = trim(name)),
    content_type TEXT NOT NULL,
    size         INTEGER NOT NULL CHECK (size > 0),
    check_state  TEXT NOT NULL DEFAULT 'ok' CHECK (check_state IN ('ok', 'pending', 'refused')),
    data         BLOB NOT NULL CHECK (length(data) = size),
    -- 0 = internal (shots, mockup files): hidden from the library
    library      INTEGER NOT NULL DEFAULT 1 CHECK (library IN (0, 1)),
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX design_assets_kind ON design_assets (kind, created_at);

CREATE TABLE design_asset_tags (
    sha256 TEXT NOT NULL REFERENCES design_assets (sha256) ON DELETE CASCADE,
    tag    TEXT NOT NULL COLLATE NOCASE CHECK (length(tag) BETWEEN 1 AND 32),
    PRIMARY KEY (sha256, tag)
);
CREATE INDEX design_asset_tags_tag ON design_asset_tags (tag);

-- Who uses an asset: a doc, a version, an approval baseline or a mockup package. Written by those
-- stories; RESTRICT makes the ref count hold even if a caller forgets to check it.
CREATE TABLE design_asset_refs (
    sha256     TEXT NOT NULL REFERENCES design_assets (sha256) ON DELETE RESTRICT,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('doc', 'version', 'approval', 'mockup')),
    owner      TEXT NOT NULL,
    PRIMARY KEY (sha256, owner_kind, owner)
);

CREATE TABLE design_collections (
    id         TEXT PRIMARY KEY CHECK (substr(id, 1, 3) = 'dc_'),
    kind       TEXT NOT NULL CHECK (kind IN ('brand_kit', 'folder')),
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100 AND name = trim(name)),
    colors     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(colors)),
    fonts      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(fonts)),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Membership does not pin an asset: deleting the asset removes it from every collection.
CREATE TABLE design_collection_items (
    collection TEXT NOT NULL REFERENCES design_collections (id) ON DELETE CASCADE,
    sha256     TEXT NOT NULL REFERENCES design_assets (sha256) ON DELETE CASCADE,
    role       TEXT CHECK (role IS NULL OR length(role) BETWEEN 1 AND 32),
    PRIMARY KEY (collection, sha256)
);
CREATE INDEX design_collection_items_sha ON design_collection_items (sha256);
