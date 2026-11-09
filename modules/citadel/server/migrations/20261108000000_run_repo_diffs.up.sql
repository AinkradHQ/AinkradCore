-- Each repo's diff against its base, as the run's runner last measured it (protocol 1.18):
-- a JSON array of `{repo, files, insertions, deletions}` in the issue's repo order.
ALTER TABLE runs ADD COLUMN diff_repos TEXT CHECK (diff_repos IS NULL OR json_valid(diff_repos));
