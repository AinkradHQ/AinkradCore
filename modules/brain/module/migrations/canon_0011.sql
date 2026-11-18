-- Re-distil and purge (B6-01), per room file. What a run still has to read, and what each batch
-- answered, until the one commit; both are deleted when the run ends. `payload` is the admitted answer
-- (candidates, dropped, grounding) and so holds text: it never leaves this encrypted file.
CREATE TABLE redistil_sources (
    run     TEXT NOT NULL,
    item_id TEXT NOT NULL,
    batch   INTEGER,              -- NULL: still to read; else the batch (seq) that took it
    PRIMARY KEY (run, item_id)
) WITHOUT ROWID;
CREATE TABLE redistil_batches (
    run     TEXT NOT NULL,
    seq     INTEGER NOT NULL,
    distil  TEXT NOT NULL,
    payload TEXT,                 -- NULL until the batch's answer passed admission and the judge
    PRIMARY KEY (run, seq)
) WITHOUT ROWID;
