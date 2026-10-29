-- Wake queue (E2.2): a coalesced request points at the pending one it was folded into, and
-- a dropped request says why. `coalesced_into` is a plain id, not a foreign key, so the
-- down migration can drop it; the survivor is never deleted by the engine.
ALTER TABLE wake_requests ADD COLUMN coalesced_into INTEGER
    CHECK ((status = 'coalesced') = (coalesced_into IS NOT NULL));
ALTER TABLE wake_requests ADD COLUMN dropped_reason TEXT
    CHECK ((status = 'dropped') = (dropped_reason IS NOT NULL) AND trim(dropped_reason) <> '');
