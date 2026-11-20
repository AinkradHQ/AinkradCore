-- The model ids a provider listed for an account when its key was added or checked (E7-3, D-19).
-- Ids only, no price: an unpriced model runs at the flagged default price. One row per account;
-- it goes with the account.
CREATE TABLE core_account_models (
    account_id INTEGER PRIMARY KEY REFERENCES core_accounts(id) ON DELETE CASCADE,
    models     TEXT    NOT NULL CHECK (json_valid(models)),
    fetched_at TEXT    NOT NULL
);
