-- An agent's profile (API minor 17): what the admin writes about it. `effort` and `sandbox` are
-- NULL until set (the harness default).
ALTER TABLE agents ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN effort TEXT CHECK (effort IN ('low', 'medium', 'high'));
ALTER TABLE agents ADD COLUMN sandbox TEXT
    CHECK (sandbox IN ('read-only', 'workspace-write', 'full-access'));
ALTER TABLE agents ADD COLUMN instructions TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN guidelines TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(guidelines) AND json_type(guidelines) = 'array');
