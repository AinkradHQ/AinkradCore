-- Companies without a profile.
ALTER TABLE companies DROP COLUMN logo_sha256;
ALTER TABLE companies DROP COLUMN work_days;
ALTER TABLE companies DROP COLUMN work_end;
ALTER TABLE companies DROP COLUMN work_start;
ALTER TABLE companies DROP COLUMN timezone;
ALTER TABLE companies DROP COLUMN website;
ALTER TABLE companies DROP COLUMN industries;
ALTER TABLE companies DROP COLUMN description;
ALTER TABLE companies DROP COLUMN color;
