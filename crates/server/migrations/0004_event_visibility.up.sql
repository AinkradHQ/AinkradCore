-- Scoped event streams (E1-04.3, handshake spec §8): each event kind is visible to one scope,
-- and a device reads only the kinds its scopes allow. A device must not learn that hidden events
-- exist, so the seq it sees is a gap-free count over its own view, never the global seq.
--
-- `event_counts` holds, per visibility scope, how many events of that scope were ever appended;
-- `event_views` copies those running totals onto each event when it is appended. A view's seq
-- for an event is the sum of the totals of the scopes the view holds, which rises by exactly
-- one at each visible event and not at all at a hidden one. A view that holds every scope sees
-- the global seq itself. `store::events::view` reads them. Neither table carries `user_id`:
-- `event_counts` is one row (the log's) and each `event_views` row describes an event.

ALTER TABLE event_kinds ADD COLUMN scope TEXT NOT NULL DEFAULT 'read'
    CHECK (scope IN ('read', 'approve', 'terminal', 'agent', 'admin'));

-- The platform's audit stream is the audit log: `admin` only, as `GET /api/v1/audit` is.
UPDATE event_kinds SET scope = 'admin' WHERE kind = 'audit';

CREATE TABLE event_counts (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    n_read     INTEGER NOT NULL,
    n_approve  INTEGER NOT NULL,
    n_terminal INTEGER NOT NULL,
    n_agent    INTEGER NOT NULL,
    n_admin    INTEGER NOT NULL
);

-- Kept for every event above the retention floor, and for the floor's own event, whose totals
-- are each view's floor (`store::events::trim`).
CREATE TABLE event_views (
    seq        INTEGER PRIMARY KEY,
    scope      TEXT    NOT NULL,
    n_read     INTEGER NOT NULL,
    n_approve  INTEGER NOT NULL,
    n_terminal INTEGER NOT NULL,
    n_agent    INTEGER NOT NULL,
    n_admin    INTEGER NOT NULL
);
CREATE INDEX event_views_scope ON event_views (scope, seq);

-- The events already there, counted from the oldest kept one (trimmed ones are not counted, so
-- a full view's seq restarts at the count kept: no client has shipped yet).
INSERT INTO event_views (seq, scope, n_read, n_approve, n_terminal, n_agent, n_admin)
SELECT e.seq, k.scope,
       sum(k.scope = 'read') OVER w, sum(k.scope = 'approve') OVER w,
       sum(k.scope = 'terminal') OVER w, sum(k.scope = 'agent') OVER w,
       sum(k.scope = 'admin') OVER w
FROM events e JOIN event_kinds k ON k.kind = e.kind
WINDOW w AS (ORDER BY e.seq);

INSERT INTO event_counts (id, n_read, n_approve, n_terminal, n_agent, n_admin)
SELECT 1, coalesce(max(n_read), 0), coalesce(max(n_approve), 0), coalesce(max(n_terminal), 0),
       coalesce(max(n_agent), 0), coalesce(max(n_admin), 0)
FROM event_views;

CREATE TRIGGER event_counts_only_rise BEFORE UPDATE ON event_counts
WHEN NEW.n_read < OLD.n_read OR NEW.n_approve < OLD.n_approve OR NEW.n_terminal < OLD.n_terminal
  OR NEW.n_agent < OLD.n_agent OR NEW.n_admin < OLD.n_admin
BEGIN
    SELECT RAISE(ABORT, 'event counts only rise');
END;

-- Every append, whichever path (`events::append`, the audit trigger, a raw INSERT), counts.
CREATE TRIGGER events_counted AFTER INSERT ON events
BEGIN
    UPDATE event_counts SET
        n_read     = n_read     + ((SELECT scope FROM event_kinds WHERE kind = NEW.kind) = 'read'),
        n_approve  = n_approve  + ((SELECT scope FROM event_kinds WHERE kind = NEW.kind) = 'approve'),
        n_terminal = n_terminal + ((SELECT scope FROM event_kinds WHERE kind = NEW.kind) = 'terminal'),
        n_agent    = n_agent    + ((SELECT scope FROM event_kinds WHERE kind = NEW.kind) = 'agent'),
        n_admin    = n_admin    + ((SELECT scope FROM event_kinds WHERE kind = NEW.kind) = 'admin');
    INSERT INTO event_views (seq, scope, n_read, n_approve, n_terminal, n_agent, n_admin)
    SELECT NEW.seq, (SELECT scope FROM event_kinds WHERE kind = NEW.kind),
           n_read, n_approve, n_terminal, n_agent, n_admin
    FROM event_counts;
END;
