-- Why a PR's checks are only partly read (its forge token may not read check runs), shown once
-- and in its merge approval; and when opening it found its head branch not pushed, after which
-- the poller waits for a later run on its issue to end (that run's push) before trying again.
ALTER TABLE issue_prs ADD COLUMN checks_note TEXT;
ALTER TABLE issue_prs ADD COLUMN unpushed_at TEXT;
