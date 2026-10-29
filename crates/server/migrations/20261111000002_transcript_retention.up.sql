-- When a run's transcript was pruned under `transcript.retention_secs`; the run stays.
ALTER TABLE runs ADD COLUMN transcript_pruned_at TEXT;
