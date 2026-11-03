-- The Core cost ledger (KAN-449, design 2026-11-02-ai-provider-accounts §7, §11b item 2, §12d): what
-- each attempt of a session cost, by account, model and harness. Moved here from Citadel's
-- `citadel_cost_events`; Citadel keeps agents, companies, projects and work, and reaches the ledger
-- through `store::costs`.
--
-- One row is one ATTEMPT (a session at an epoch, on an account), a delta and never a running total, so
-- a runner restart or a failover cannot lose or double a turn. `idempotency_key` makes a retried
-- report a no-op. A row is insert-only (triggers below): a correction is a new row that points at the
-- one it corrects.
--
-- `account_id` has NO foreign key: the history outlives the account, and ids are AUTOINCREMENT so one
-- is never reused. `legacy_account_id` carries the account id of Citadel's own store until that store
-- moves into `core_accounts` (the account port); it is dropped then.
-- A subject is opaque text (like `core_pool_bindings.agent`): Core has no foreign key into any module.

-- A price in millionths of a dollar per million tokens, versioned: a new price is a new row and a
-- cost event keeps the rates that priced it. Built-in providers carry no prices in code (none are
-- invented); a user definition's own `models` list is the fallback when no row exists here.
CREATE TABLE core_prices (
    id                    INTEGER PRIMARY KEY,
    user_id               INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    provider              TEXT    NOT NULL CHECK (length(provider) BETWEEN 1 AND 32),
    model                 TEXT    NOT NULL CHECK (length(model) BETWEEN 1 AND 80),
    version               INTEGER NOT NULL CHECK (version >= 1),
    input_per_mtok_micro  INTEGER NOT NULL CHECK (input_per_mtok_micro BETWEEN 0 AND 1000000000),
    output_per_mtok_micro INTEGER NOT NULL CHECK (output_per_mtok_micro BETWEEN 0 AND 1000000000),
    cache_per_mtok_micro  INTEGER NOT NULL CHECK (cache_per_mtok_micro BETWEEN 0 AND 1000000000),
    priced_at             TEXT    NOT NULL CHECK (julianday(priced_at) IS NOT NULL),
    created_at            TEXT    NOT NULL,
    UNIQUE (provider, model, version)
);

CREATE TABLE core_cost_events (
    id                INTEGER PRIMARY KEY,
    user_id           INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    session           TEXT    NOT NULL CHECK (length(session) BETWEEN 1 AND 64),
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    account_id        INTEGER,
    legacy_account_id INTEGER,
    provider          TEXT    NOT NULL CHECK (length(provider) BETWEEN 1 AND 32),
    harness           TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model             TEXT    NOT NULL CHECK (length(model) BETWEEN 1 AND 80),
    input_tokens      INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens     INTEGER NOT NULL CHECK (output_tokens >= 0),
    cache_tokens      INTEGER NOT NULL CHECK (cache_tokens >= 0),
    cost_usd_micros   INTEGER,
    -- How the cost was found: from the list price in force, as the provider reported it, or as the
    -- provider's bill corrected it later; `unpriced` (cost NULL, never 0) when no price was known.
    basis             TEXT    NOT NULL CHECK (basis IN
                      ('list_price', 'provider_reported', 'billing_corrected', 'unpriced')),
    -- 1 when the turn was interrupted: its tokens are what the meter had, not a final count.
    approximate       INTEGER NOT NULL DEFAULT 0 CHECK (approximate IN (0, 1)),
    -- The rates that priced a `list_price` row (the row keeps them; a later price never re-prices it).
    rate_input        INTEGER CHECK (rate_input >= 0),
    rate_output       INTEGER CHECK (rate_output >= 0),
    rate_cache        INTEGER CHECK (rate_cache >= 0),
    priced_at         TEXT,
    corrects_id       INTEGER REFERENCES core_cost_events(id),
    idempotency_key   TEXT    NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    occurred_at       TEXT    NOT NULL CHECK (julianday(occurred_at) IS NOT NULL),
    created_at        TEXT    NOT NULL,
    CHECK ((basis = 'unpriced') = (cost_usd_micros IS NULL)),
    -- Only a correction may be negative (the bill came in lower than the estimate).
    CHECK (basis = 'billing_corrected' OR cost_usd_micros IS NULL OR cost_usd_micros >= 0),
    CHECK ((basis = 'billing_corrected') = (corrects_id IS NOT NULL)),
    CHECK ((basis = 'list_price') = (rate_input IS NOT NULL AND rate_output IS NOT NULL
                                     AND rate_cache IS NOT NULL AND priced_at IS NOT NULL))
);

CREATE INDEX core_cost_events_session ON core_cost_events (session, epoch);
CREATE INDEX core_cost_events_account ON core_cost_events (account_id, occurred_at);
CREATE INDEX core_cost_events_legacy_account ON core_cost_events (legacy_account_id, occurred_at)
    WHERE legacy_account_id IS NOT NULL;

-- Who an event counts against: the account and each pool it was in (written at record time, so a
-- later change of membership never moves history), and what the caller attributes it to. Several
-- departments, say, may apply to one event, which is why this is rows and not columns.
CREATE TABLE core_cost_subjects (
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    event_id   INTEGER NOT NULL REFERENCES core_cost_events(id),
    kind       TEXT    NOT NULL CHECK (kind IN
               ('account', 'pool', 'agent', 'company', 'department', 'project', 'sprint', 'issue')),
    subject_id TEXT    NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 64),
    PRIMARY KEY (event_id, kind, subject_id)
) WITHOUT ROWID;

CREATE INDEX core_cost_subjects_subject ON core_cost_subjects (kind, subject_id);

CREATE TRIGGER core_prices_insert_only BEFORE UPDATE ON core_prices
BEGIN SELECT RAISE(ABORT, 'prices are insert-only: set a new version'); END;
CREATE TRIGGER core_prices_no_delete BEFORE DELETE ON core_prices
BEGIN SELECT RAISE(ABORT, 'prices are insert-only: set a new version'); END;
CREATE TRIGGER core_cost_events_insert_only BEFORE UPDATE ON core_cost_events
BEGIN SELECT RAISE(ABORT, 'cost events are insert-only'); END;
CREATE TRIGGER core_cost_events_no_delete BEFORE DELETE ON core_cost_events
BEGIN SELECT RAISE(ABORT, 'cost events are insert-only'); END;
CREATE TRIGGER core_cost_subjects_insert_only BEFORE UPDATE ON core_cost_subjects
BEGIN SELECT RAISE(ABORT, 'cost subjects are insert-only'); END;
CREATE TRIGGER core_cost_subjects_no_delete BEFORE DELETE ON core_cost_subjects
BEGIN SELECT RAISE(ABORT, 'cost subjects are insert-only'); END;

-- Rolling limits per account (Citadel's E15.2, `citadel_account_limits`): a cap of tokens or messages
-- over a window. Messages are counted from `core_account_events`, tokens from the ledger.
CREATE TABLE core_account_limits (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    account_id   INTEGER NOT NULL REFERENCES core_accounts(id) ON DELETE CASCADE,
    unit         TEXT    NOT NULL CHECK (unit IN ('tokens', 'messages')),
    window_secs  INTEGER NOT NULL CHECK (window_secs BETWEEN 1 AND 31622400),
    cap          INTEGER NOT NULL CHECK (cap > 0),
    warn_percent INTEGER CHECK (warn_percent IS NULL OR warn_percent BETWEEN 1 AND 100),
    UNIQUE (account_id, unit, window_secs)
);

CREATE TABLE core_account_events (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    account_id INTEGER NOT NULL REFERENCES core_accounts(id) ON DELETE CASCADE,
    session    TEXT    CHECK (session IS NULL OR length(session) BETWEEN 1 AND 64),
    kind       TEXT    NOT NULL CHECK (kind IN ('message', 'drop')),
    at         TEXT    NOT NULL CHECK (julianday(at) IS NOT NULL)
);

CREATE INDEX core_account_events_window ON core_account_events (account_id, kind, at);
