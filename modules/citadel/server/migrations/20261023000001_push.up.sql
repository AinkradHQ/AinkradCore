-- APNs (E10.4): a device key's push token (hex, from the app) and whether it is a
-- development build's (the sandbox gateway), and how far the pusher has read the events.
ALTER TABLE device_keys ADD COLUMN push_token TEXT
    CHECK (push_token IS NULL OR (length(push_token) BETWEEN 32 AND 200
                                  AND push_token NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE device_keys ADD COLUMN push_sandbox INTEGER NOT NULL DEFAULT 0
    CHECK (push_sandbox IN (0, 1));

CREATE TABLE push_cursor (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    after INTEGER NOT NULL
);
