-- A live invite would be a plain pairing with no expiry once the flag is gone: end it first.
UPDATE core_pairings SET status = 'burned' WHERE invite = 1 AND status = 'live';
ALTER TABLE core_pairings DROP COLUMN invite;
