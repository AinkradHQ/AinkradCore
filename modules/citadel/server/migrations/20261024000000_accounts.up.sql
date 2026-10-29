-- Provider accounts (E15.1, decision #41): one pool owned by the admin, assigned to companies
-- (many-to-many). The server picks an account per run (`runs.account_id`); usage is
-- attributed to it (`cost_events.account_id`) and, through the run's agent, to its company.
--
-- No secret is stored: `credential_ref` names a file under a runner host's credentials dir,
-- read there when the run starts, and `credential_env` the harness variable it goes in;
-- `config_dir` is the account's own harness config dir under the runner's config root (a
-- subscription login lives there).
--
-- Billing moves from the harness (E7.3) to the account: a run with an account is billed as
-- its account; `harness_billing` stays for runs with none (a harness with no accounts in the
-- pool runs on the runner's own login, as before), and is a new account's default.
CREATE TABLE accounts (
    id             INTEGER PRIMARY KEY,
    user_id        INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    harness        TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    label          TEXT    NOT NULL UNIQUE CHECK (label <> ''),
    credential_ref TEXT    CHECK (credential_ref <> ''),
    credential_env TEXT    CHECK (credential_env <> ''),
    config_dir     TEXT    NOT NULL CHECK (config_dir <> ''),
    billing        TEXT    NOT NULL CHECK (billing IN ('metered', 'subscription')),
    status         TEXT    NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active', 'limited', 'unhealthy', 'disabled')),
    status_reason  TEXT,
    last_used_at   TEXT,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((status = 'active') = (status_reason IS NULL)),
    CHECK ((credential_ref IS NULL) = (credential_env IS NULL))
);

CREATE TABLE account_companies (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    PRIMARY KEY (account_id, company_id)
);
CREATE INDEX account_companies_company ON account_companies (company_id);

ALTER TABLE runs ADD COLUMN account_id INTEGER REFERENCES accounts(id);
CREATE INDEX runs_account ON runs (account_id);
ALTER TABLE cost_events ADD COLUMN account_id INTEGER REFERENCES accounts(id);
CREATE INDEX cost_events_account ON cost_events (account_id, created_at);

-- A run only ever works as an account of its own company, on the account's harness.
CREATE TRIGGER runs_account_company BEFORE UPDATE OF account_id ON runs
WHEN NEW.account_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'account is not assigned to the run''s company')
    WHERE NOT EXISTS (SELECT 1 FROM account_companies ac JOIN agents a
                      ON a.company_id = ac.company_id
                      WHERE ac.account_id = NEW.account_id AND a.id = NEW.agent_id);
    SELECT RAISE(ABORT, 'account is for another harness')
    WHERE (SELECT harness FROM accounts WHERE id = NEW.account_id) <> NEW.harness;
END;
