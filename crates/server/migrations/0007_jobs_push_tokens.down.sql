UPDATE core_devices SET push_token = NULL, push_sandbox = 0;
UPDATE core_devices SET push_token = t.token, push_sandbox = t.sandbox
FROM core_push_tokens t
WHERE t.device_seq = core_devices.seq AND t.provider = 'apns'
  AND length(t.token) BETWEEN 32 AND 200 AND t.token NOT GLOB '*[^0-9a-f]*';
DROP TABLE core_push_tokens;
DROP TABLE core_job_runs;
DROP TABLE core_jobs;
