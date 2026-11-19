-- E11-4 (D-29): one row per "draw 3 directions" run of the Design composer. The AI session answers
-- with JSON; the Core turns it into three frames on the canvas. `directions` is the answer's
-- names and summaries only (what the picker shows), never the prompt's or the model's raw text.
CREATE TABLE design_composes (
    id         TEXT PRIMARY KEY,
    doc        TEXT NOT NULL REFERENCES design_docs (id) ON DELETE CASCADE,
    session    TEXT,
    prompt     TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('drawing', 'applying', 'done', 'failed')),
    reason     TEXT NOT NULL DEFAULT '',
    directions TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(directions)),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX design_composes_by_doc ON design_composes (doc, created_at);
