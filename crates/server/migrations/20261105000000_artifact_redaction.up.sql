-- Artifact redaction (E15.18 follow-up of E15.12): a text artifact is scanned for secrets and
-- redacted before it is hashed and stored; `redactions` is how many markers its stored content
-- holds. Any other type (images, PDF, zip) is stored as it is and marked `unscanned`, as is
-- every artifact published before this migration.
ALTER TABLE artifacts ADD COLUMN redactions INTEGER NOT NULL DEFAULT 0 CHECK (redactions >= 0);
ALTER TABLE artifacts ADD COLUMN unscanned INTEGER NOT NULL DEFAULT 0 CHECK (unscanned IN (0, 1));
UPDATE artifacts SET unscanned = 1;
