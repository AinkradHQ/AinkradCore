DROP TABLE brain_session_cursor;
DROP TABLE brain_session_loaded;
ALTER TABLE brain_room_policy DROP COLUMN daily_distils;
ALTER TABLE brain_room_policy DROP COLUMN retention_days;
ALTER TABLE brain_distils DROP COLUMN of_session;
ALTER TABLE brain_distils DROP COLUMN "trigger";
