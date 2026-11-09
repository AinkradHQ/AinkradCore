-- Notification preferences per company (parity API B2, item 6): which event goes to which
-- channel (a row is a choice; no row is the default, `ops::notify_default`), and quiet hours.
-- Event and channel names are checked by the API, not here, so a new one is not a migration.
CREATE TABLE notification_prefs (
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    event      TEXT    NOT NULL CHECK (event <> ''),
    channel    TEXT    NOT NULL CHECK (channel <> ''),
    enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    PRIMARY KEY (company_id, event, channel)
) WITHOUT ROWID;

-- Minutes from midnight; the window wraps past midnight when start is after end.
CREATE TABLE notification_quiet (
    company_id   INTEGER PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
    quiet_start  INTEGER NOT NULL DEFAULT 1320 CHECK (quiet_start BETWEEN 0 AND 1439),
    quiet_end    INTEGER NOT NULL DEFAULT 420 CHECK (quiet_end BETWEEN 0 AND 1439),
    quiet_on     INTEGER NOT NULL DEFAULT 0 CHECK (quiet_on IN (0, 1)),
    breakthrough TEXT    NOT NULL DEFAULT 'stalled' CHECK (breakthrough <> '')
);
