-- Distillation (E6): which run took a source, and who decided a candidate.
ALTER TABLE sources ADD COLUMN distilled TEXT;
ALTER TABLE records ADD COLUMN reviewed_at TEXT;
ALTER TABLE records ADD COLUMN decided_by TEXT;
ALTER TABLE records ADD COLUMN distil TEXT;
