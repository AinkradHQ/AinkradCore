-- A refusal deletes by content hash alone; the primary key leads with the model, so without this
-- every deleted hash was a scan of the whole file.
CREATE INDEX vectors_hash ON vectors(content_hash);
