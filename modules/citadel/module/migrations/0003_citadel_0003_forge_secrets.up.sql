-- S6: a forge or Linear credential is a secrets-broker name (`citadel.<name>`), never a server
-- file. The old columns held paths, which are not names, so any forge or Linear config written
-- before this is cleared (the module had no data: a fresh start); the repos stay.
UPDATE citadel_project_repos
   SET forge_kind = NULL, forge_api_url = NULL, forge_repo = NULL, forge_token_file = NULL
 WHERE forge_kind IS NOT NULL;
DELETE FROM citadel_project_linear;
ALTER TABLE citadel_project_repos RENAME COLUMN forge_token_file TO forge_secret;
ALTER TABLE citadel_project_linear RENAME COLUMN token_file TO secret;

-- Hosts a project's forge or Linear API may be on besides the public ones (GitHub, GitLab.com,
-- Linear): an operator adds one with a step-up, for a self-hosted forge.
CREATE TABLE citadel_forge_hosts (
    host       TEXT PRIMARY KEY CHECK (host <> '' AND length(host) <= 253
                                       AND host NOT GLOB '*[^a-z0-9.-]*' AND host GLOB '*.*'
                                       AND host NOT GLOB '.*' AND host NOT GLOB '*.'),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;
