-- What a run's collectors took, kept apart from the source's own cursor until the run is committed:
-- an abandoned or expired run leaves the cursor where it was, so nothing is lost.
CREATE TABLE brain_run_cursors (
    run    TEXT NOT NULL,
    source TEXT NOT NULL,
    cursor TEXT NOT NULL,
    PRIMARY KEY (run, source)
);
