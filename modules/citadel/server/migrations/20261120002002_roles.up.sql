-- Roles (parity API B2, item 4): what a company hires for, with the defaults a new agent of the
-- role starts on. `skills` is a JSON array of skill names.
CREATE TABLE roles (
    id            INTEGER PRIMARY KEY,
    company_id    INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL CHECK (name <> ''),
    purpose       TEXT    NOT NULL DEFAULT '',
    icon          TEXT    NOT NULL DEFAULT '',
    harness       TEXT    CHECK (harness IS NULL OR harness IN ('claude', 'codex', 'opencode', 'agy')),
    model         TEXT    CHECK (model IS NULL OR model <> ''),
    budget_tokens INTEGER CHECK (budget_tokens IS NULL OR budget_tokens >= 0),
    skills        TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(skills)),
    instructions  TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (company_id, name)
);
