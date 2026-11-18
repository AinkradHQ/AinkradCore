-- B5-02 review: `support` is the number of distinct origins (one AI session, or one document by
-- device + path) that cite a record, not a count of repeats. A citation from a session the Brain had
-- given the record to (`brain_session_loaded`) is kept but marked `echo` and never counts.
ALTER TABLE record_sources ADD COLUMN echo INTEGER NOT NULL DEFAULT 0;

-- Recount every record once (`merge::recount` is the same expression). No echo is known for older
-- citations: nothing wrote `brain_session_loaded` before this release.
UPDATE records SET support = max(1, (
    SELECT count(DISTINCT coalesce(s.device || char(10) || s.path, rs.source))
    FROM record_sources rs LEFT JOIN sources s ON s.item_id = rs.source
    WHERE rs.record = records.id AND rs.echo = 0));
