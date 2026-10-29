-- The sha of the branch's last push the runner confirmed (`branch_pushed`). A requested PR with
-- it set is due at once, even while a later run on its issue is live: the branch is on the
-- forge, so the poller opens the PR within one pass instead of waiting for the issue to go quiet.
-- Set by the push; cleared when the request is made again, unless it is still waiting.
ALTER TABLE issue_prs ADD COLUMN pushed_sha TEXT;
