-- Company profile (API minor 17): how a company presents itself (colour, description,
-- industries, website, an uploaded logo stored content-addressed with the artifacts) and when
-- it works (IANA time zone, working hours as minutes from midnight, working days as a bitmask,
-- bit 0 Monday … bit 6 Sunday). Every field is optional; the server checks them.
ALTER TABLE companies ADD COLUMN color TEXT;
ALTER TABLE companies ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE companies ADD COLUMN industries TEXT NOT NULL DEFAULT '[]';
ALTER TABLE companies ADD COLUMN website TEXT;
ALTER TABLE companies ADD COLUMN timezone TEXT;
ALTER TABLE companies ADD COLUMN work_start INTEGER;
ALTER TABLE companies ADD COLUMN work_end INTEGER;
ALTER TABLE companies ADD COLUMN work_days INTEGER;
ALTER TABLE companies ADD COLUMN logo_sha256 TEXT;
