-- Uploaded avatar blobs on disk are left for the admin; nothing points at them any more.
ALTER TABLE agents DROP COLUMN avatar_sha256;
ALTER TABLE agents DROP COLUMN palette_id;
ALTER TABLE agents DROP COLUMN figure_version;
DROP TABLE avatar_palettes;
DELETE FROM settings WHERE key = 'avatar.max_bytes';
