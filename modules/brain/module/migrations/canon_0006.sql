-- Brain v2 schema (plan 2026-11-18, B2-01): the memory layer. Forward-only; safe on a room file that
-- already holds records (every new column is nullable or has a constant default, and every backfill
-- below is a plain UPDATE / INSERT OR IGNORE, so a re-run changes nothing).
ALTER TABLE records ADD COLUMN support       INTEGER NOT NULL DEFAULT 1;
ALTER TABLE records ADD COLUMN last_seen_at  TEXT;
ALTER TABLE records ADD COLUMN body_norm     TEXT;
ALTER TABLE records ADD COLUMN valid_from    TEXT;
ALTER TABLE records ADD COLUMN valid_to      TEXT;
ALTER TABLE records ADD COLUMN supersedes    TEXT;
ALTER TABLE records ADD COLUMN superseded_by TEXT;
ALTER TABLE records ADD COLUMN admit_score   REAL;
ALTER TABLE records ADD COLUMN origin        TEXT NOT NULL DEFAULT 'distil';
ALTER TABLE records ADD COLUMN edited_by_person INTEGER NOT NULL DEFAULT 0;
ALTER TABLE records ADD COLUMN archived_at   TEXT;
ALTER TABLE sources ADD COLUMN compacted_at  TEXT;
ALTER TABLE sources ADD COLUMN redistil      TEXT;

CREATE INDEX records_current ON records(status, valid_to, type);
CREATE INDEX records_norm ON records(type, body_norm);

-- The citations of a record, one row each (`position` = order in the record's list). `source_ids`
-- JSON keeps being written for one release for old readers; nothing new reads it.
CREATE TABLE record_sources (
    record   TEXT NOT NULL,
    source   TEXT NOT NULL,
    position INTEGER NOT NULL,
    PRIMARY KEY (record, source)
) WITHOUT ROWID;

-- Every automatic write is a change set with row images, so it can be undone (B2-02 writes them).
CREATE TABLE changes (
    id        TEXT PRIMARY KEY,
    kind      TEXT NOT NULL,
    summary   TEXT NOT NULL,
    counts    TEXT NOT NULL DEFAULT '{}',
    at        TEXT NOT NULL,
    undone_at TEXT
);
CREATE TABLE change_rows (
    change TEXT NOT NULL REFERENCES changes(id),
    seq    INTEGER NOT NULL,
    record TEXT NOT NULL,
    before TEXT,
    after  TEXT,
    PRIMARY KEY (change, seq)
) WITHOUT ROWID;

-- Memory = the facts in force: accepted, not superseded, not archived. Every reader uses this view.
CREATE VIEW memory AS
    SELECT * FROM records
    WHERE status = 'accepted' AND valid_to IS NULL AND archived_at IS NULL;

-- Backfill. A malformed `source_ids` (never written by this code, but the file may be old) reads as [].
INSERT OR IGNORE INTO record_sources (record, source, position)
    SELECT r.id, j.value, j.key
    FROM records r,
         json_each(CASE WHEN json_valid(r.source_ids) THEN r.source_ids ELSE '[]' END) j
    WHERE j.type = 'text';

-- Exact-dedup key: ASCII-lowercase, control whitespace to spaces, runs collapsed (six passes cover
-- runs up to 64), trimmed. ponytail: longer runs / non-ASCII case stay as written; the Rust
-- normaliser (B4-01) must produce the same string for the same input or re-run this backfill.
UPDATE records SET body_norm = lower(trim(
    replace(replace(replace(replace(replace(replace(
        replace(replace(replace(body, char(13), ' '), char(10), ' '), char(9), ' '),
        '  ', ' '), '  ', ' '), '  ', ' '), '  ', ' '), '  ', ' '), '  ', ' ')))
    WHERE body_norm IS NULL;

-- Earliest and newest cited source time; a record that cites nothing is valid from its creation.
UPDATE records SET
    valid_from   = coalesce((SELECT min(s.started_at) FROM record_sources rs
                             JOIN sources s ON s.item_id = rs.source WHERE rs.record = records.id),
                            created_at),
    last_seen_at = (SELECT max(s.started_at) FROM record_sources rs
                    JOIN sources s ON s.item_id = rs.source WHERE rs.record = records.id)
    WHERE valid_from IS NULL;

-- Provenance from what is already recorded: an AI session's proposal (`distil` = `ai:<session>`),
-- else a person's decision (`decided_by` is a device id; `auto` = the room policy decided).
UPDATE records SET
    origin = CASE WHEN distil LIKE 'ai:%' THEN 'ai'
                  WHEN decided_by IS NOT NULL AND decided_by <> 'auto' THEN 'person'
                  ELSE 'distil' END,
    edited_by_person = CASE WHEN decided_by IS NOT NULL AND decided_by <> 'auto' THEN 1 ELSE 0 END
    WHERE origin = 'distil' AND edited_by_person = 0;
