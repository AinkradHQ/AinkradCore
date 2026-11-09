-- A device's replay walks only the scopes it may see, by this index, so the work follows the
-- visible events and never the hidden ones (step-up review S6).
CREATE INDEX event_views_scope_seq ON event_views (scope, seq);
