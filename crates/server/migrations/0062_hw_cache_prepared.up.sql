-- The warm cache's "prepared" marker (Core 0.10, E15-3): a blake3 of the project's lockfiles as
-- they were when `prepare` (`npm ci` ...) last ran there and the job succeeded. NULL: never
-- prepared. A different lockfile hash runs `prepare` again.
ALTER TABLE core_hw_cache ADD COLUMN prepared BLOB CHECK (prepared IS NULL OR length(prepared) = 32);
