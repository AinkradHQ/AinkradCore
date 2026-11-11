ALTER TABLE core_secrets DROP COLUMN use_count;
ALTER TABLE core_secrets DROP COLUMN last_used_at;
ALTER TABLE core_secrets DROP COLUMN group_id;
ALTER TABLE core_secrets DROP COLUMN file_mode;
ALTER TABLE core_secrets DROP COLUMN file_name;
ALTER TABLE core_secrets DROP COLUMN description;
ALTER TABLE core_secrets DROP COLUMN kind;
DROP TABLE core_secret_groups;
