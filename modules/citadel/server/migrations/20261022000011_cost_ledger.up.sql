-- The cost ledger (E7.3, #15): usage becomes dollars only where they are known.
--
-- A cost event's dollars come from the harness's own report (Claude, OpenCode), or else from
-- the latest version of the price of its run's harness and model (`prices`, set with
-- `ainkrad-core-server price set`), or not at all: then `cost_usd_micros` stays NULL with
-- `priced = 0`, never 0, and reports count the run as unpriced. There is no built-in rate card.
-- A harness billed by subscription (`harness_billing`) records tokens only, `billing =
-- 'subscription'`, with no dollars: a subscription has no per-token price to report.
CREATE TABLE prices (
    id                     INTEGER PRIMARY KEY,
    harness                TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model                  TEXT    NOT NULL CHECK (model <> ''),
    version                INTEGER NOT NULL CHECK (version >= 1),
    -- Millionths of a US dollar per million tokens: $3.00 / Mtok is 3000000.
    input_micros_per_mtok  INTEGER NOT NULL CHECK (input_micros_per_mtok >= 0),
    output_micros_per_mtok INTEGER NOT NULL CHECK (output_micros_per_mtok >= 0),
    cache_micros_per_mtok  INTEGER NOT NULL CHECK (cache_micros_per_mtok >= 0),
    created_at             TEXT    NOT NULL,
    UNIQUE (harness, model, version)
);

CREATE TABLE harness_billing (
    harness TEXT PRIMARY KEY CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    billing TEXT NOT NULL CHECK (billing IN ('metered', 'subscription'))
);

-- Which price priced it (NULL: reported by the harness, or unpriced), and how it is billed.
ALTER TABLE cost_events ADD COLUMN price_id INTEGER REFERENCES prices(id);
ALTER TABLE cost_events ADD COLUMN billing TEXT NOT NULL DEFAULT 'metered'
    CHECK (billing IN ('metered', 'subscription'));
CREATE INDEX cost_events_price ON cost_events (price_id);
