-- The room Overview (summary, rules, instructions): one row. `overview` is the model's validated
-- JSON; `selection` the item ids the model was shown (the only ids a rule may cite);
-- `instructions` the editable text, approved when `instructions_approved_at` is set.
CREATE TABLE room_overview (
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    state                    TEXT NOT NULL DEFAULT 'not_written',
    detail                   TEXT NOT NULL DEFAULT '',
    overview                 TEXT,
    selection                TEXT NOT NULL DEFAULT '[]',
    written_at               TEXT,
    model                    TEXT,
    instructions             TEXT,
    instructions_approved_at TEXT,
    updated_at               TEXT NOT NULL
);
