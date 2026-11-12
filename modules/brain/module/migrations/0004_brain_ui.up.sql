-- What the Brain screens show: items taken per source, and the fewest sources an auto-accepted
-- candidate must cite.
ALTER TABLE brain_sources ADD COLUMN items INTEGER NOT NULL DEFAULT 0;
ALTER TABLE brain_room_policy ADD COLUMN min_sources INTEGER NOT NULL DEFAULT 1 CHECK (min_sources BETWEEN 1 AND 20);
