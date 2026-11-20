-- Models a person switched off for one account (E7-2b). A model is allowed unless it has a row here,
-- so every existing account keeps working. A row goes with its account.
CREATE TABLE core_account_model_denied (
    account_id INTEGER NOT NULL REFERENCES core_accounts(id) ON DELETE CASCADE,
    model      TEXT    NOT NULL,
    denied_at  TEXT    NOT NULL,
    PRIMARY KEY (account_id, model)
);
