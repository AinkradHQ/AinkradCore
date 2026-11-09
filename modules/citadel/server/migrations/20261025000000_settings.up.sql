-- Configurable limits (E15.17, decision #52): a value per (key, scope); the registry in
-- `ainkrad_core::settings` holds each key's default, bounds and allowed scopes, and the most
-- specific scope wins. `scope_id` is 0 for the server. Every set and reset is audited
-- (`setting.set` / `setting.reset`), which is the change history.
CREATE TABLE settings (
    key             TEXT    NOT NULL CHECK (key <> ''),
    scope_kind      TEXT    NOT NULL CHECK (scope_kind IN ('server', 'company', 'project',
                    'runner', 'account')),
    scope_id        INTEGER NOT NULL CHECK ((scope_kind = 'server') = (scope_id = 0)),
    value           TEXT    NOT NULL CHECK (json_valid(value)),
    updated_by_kind TEXT    NOT NULL CHECK (updated_by_kind IN ('user', 'agent', 'runner',
                    'system')),
    updated_by_id   INTEGER,
    updated_at      TEXT    NOT NULL,
    PRIMARY KEY (key, scope_kind, scope_id)
);

-- Approval deadlines per kind (E7.1) become settings: what was set moves over, and the table
-- goes. NULL (no deadline) is 0.
INSERT INTO settings (key, scope_kind, scope_id, value, updated_by_kind, updated_at)
SELECT 'approval.deadline.' || kind, 'server', 0, coalesce(deadline_secs, 0), 'system',
       strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM approval_deadlines
WHERE coalesce(deadline_secs, 0) <> iif(kind = 'permission_escalation', 900, 0);
DROP TABLE approval_deadlines;
