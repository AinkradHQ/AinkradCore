-- A free-text name for an account (`Work Claude`), beside its slug `label`. Absent: clients show the
-- provider's name. The API trims it and refuses control characters; the column holds the length.
ALTER TABLE core_accounts ADD COLUMN display_name TEXT
    CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 64);
-- A sign-in carries the name to the account it makes.
ALTER TABLE core_account_logins ADD COLUMN display_name TEXT
    CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 64);
