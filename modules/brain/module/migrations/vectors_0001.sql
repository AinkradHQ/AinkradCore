-- Sentence vectors of items under review, by model and content hash, so a restart does not embed
-- everything again. A vector carries the item's meaning: this file is encrypted with the brain key
-- like item text, and a refused item's row is deleted. Rows of another model are dropped on write.
CREATE TABLE vectors (
    model        TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    vec          BLOB NOT NULL,
    PRIMARY KEY (model, content_hash)
);
