-- Leyline Y4-03: why a host did not run (refused by the gate, not for the command, cancelled). A fixed
-- sentence, never output. Results stay per host in the existing columns.
ALTER TABLE leyline_run_hosts ADD COLUMN reason TEXT;
