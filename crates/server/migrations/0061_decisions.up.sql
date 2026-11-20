-- The Decisions service's cache (Core 0.10, E15-0): `key` is blake3 of the consumer, provider,
-- options, redacted text, redacted facts and the context hash, so a row holds no text; `scores` is
-- a JSON array of `[option, score]` pairs. The scheduler trims expired rows.
CREATE TABLE core_decision_cache (
    key        BLOB PRIMARY KEY CHECK (length(key) = 32),
    consumer   TEXT NOT NULL,
    scores     TEXT NOT NULL CHECK (json_valid(scores) AND json_type(scores) = 'array'),
    provider   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX core_decision_cache_expires ON core_decision_cache (expires_at);
