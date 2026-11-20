-- The hardware the Core first saw from a runner (E15 security review M8): its later reports are
-- held to it, so a runner cannot claim more cores, memory or job slots than it first showed.
ALTER TABLE core_hardware_prefs ADD COLUMN first_cores INTEGER CHECK (first_cores IS NULL OR first_cores >= 0);
ALTER TABLE core_hardware_prefs ADD COLUMN first_mem_mb INTEGER CHECK (first_mem_mb IS NULL OR first_mem_mb >= 0);
