-- The blobs on disk are left for the admin; nothing points at them any more.
DROP TABLE artifact_reads;
DROP TABLE artifacts;
DELETE FROM settings WHERE key IN ('artifact.max_file_bytes', 'artifact.company_quota_bytes');
