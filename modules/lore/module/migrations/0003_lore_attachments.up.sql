-- Lore R1-05: attachments. Content-addressed BLOBs; there is no link table, a note references one by the
-- text `lore-attachment:<sha256>` in its Markdown, and the sweep counts references from the text. The
-- Core decides `content_type` from the bytes; nothing the client sent is stored. Nothing here is a secret.
CREATE TABLE lore_attachments (
    sha256       TEXT PRIMARY KEY CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    content_type TEXT NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg', 'image/gif',
                     'image/webp', 'image/heic', 'application/pdf')),
    size         INTEGER NOT NULL CHECK (size BETWEEN 1 AND 10485760),
    data         BLOB NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
