-- Disk (E15.9): each runner's last disk report (JSON: used, cap, caches, mirrors, worktrees,
-- full) and when it arrived.
ALTER TABLE runners ADD COLUMN disk TEXT CHECK (disk IS NULL OR json_valid(disk));
ALTER TABLE runners ADD COLUMN disk_at TEXT;
