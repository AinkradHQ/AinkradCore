-- Design V4-02: mockup packages (T10). A package is a `kind = 'mockup'` doc plus its files. The bytes
-- live in `design_assets` (kind `mockup_file`, library = 0, content-addressed), this table only maps
-- a validated package path to them. `design_docs.manifest` stays NULL while the package is a draft
-- and is set once, when the package is sealed. Nothing here holds a secret.

CREATE TABLE design_mockup_files (
    doc    TEXT NOT NULL REFERENCES design_docs (id) ON DELETE CASCADE,
    -- case-insensitive: two paths that differ only by case are one file (no ambiguity on macOS)
    path   TEXT NOT NULL COLLATE NOCASE CHECK (length(path) BETWEEN 1 AND 200),
    sha256 TEXT NOT NULL REFERENCES design_assets (sha256) ON DELETE RESTRICT,
    size   INTEGER NOT NULL CHECK (size > 0),
    PRIMARY KEY (doc, path)
);
CREATE INDEX design_mockup_files_sha ON design_mockup_files (sha256);
