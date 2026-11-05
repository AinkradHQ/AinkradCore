-- The auth gateway's API (KAN-435 G7, design 2026-11-04 §5.1 part 2).
--
-- `wire` is the API dialect the gateway speaks to a provider's upstream (a closed set, in code); a
-- user definition names one, which must be its harness's own. `key_prefix` is the shape a user
-- definition's keys start with, so the broker can tell its key from a built-in's and bind it to the
-- definition's host (`key_host_problem`); NULL for a definition that holds no key. Definitions stored
-- before this get the wire their harness speaks.
ALTER TABLE core_provider_defs ADD COLUMN wire TEXT NOT NULL DEFAULT 'anthropic-messages'
    CHECK (wire IN ('anthropic-messages', 'openai-responses', 'gemini-generate'));
UPDATE core_provider_defs SET wire = CASE harness
    WHEN 'codex' THEN 'openai-responses' WHEN 'agy' THEN 'gemini-generate'
    ELSE 'anthropic-messages' END;
ALTER TABLE core_provider_defs ADD COLUMN key_prefix TEXT
    CHECK (key_prefix IS NULL OR length(key_prefix) BETWEEN 6 AND 32);

-- What one session may spend through this account (NULL: only the budgets limit it), and the last
-- one-shot `gateway.test` of its key: when, and the status class it answered (never provider text).
ALTER TABLE core_accounts ADD COLUMN session_max_tokens INTEGER
    CHECK (session_max_tokens IS NULL OR session_max_tokens > 0);
ALTER TABLE core_accounts ADD COLUMN session_max_usd_micros INTEGER
    CHECK (session_max_usd_micros IS NULL OR session_max_usd_micros > 0);
ALTER TABLE core_accounts ADD COLUMN last_test_at TEXT;
ALTER TABLE core_accounts ADD COLUMN last_test_result TEXT
    CHECK (last_test_result IS NULL OR length(last_test_result) <= 32);

-- An account may now belong to a user-defined provider, so the column's three-name CHECK goes. A
-- column's own CHECK is dropped with the column; the copy keeps the data and the name (the table is
-- not rebuilt: the pool seats, limits and events that reference it would be cascaded away by the
-- implicit delete of a DROP TABLE). The default is only what the ADD needs; every row is set next.
ALTER TABLE core_accounts ADD COLUMN provider_id TEXT NOT NULL DEFAULT 'anthropic'
    CHECK (length(provider_id) BETWEEN 1 AND 32 AND substr(provider_id, 1, 1) GLOB '[a-z]'
           AND provider_id NOT GLOB '*[^a-z0-9-]*');
UPDATE core_accounts SET provider_id = provider;
ALTER TABLE core_accounts DROP COLUMN provider;
ALTER TABLE core_accounts RENAME COLUMN provider_id TO provider;
