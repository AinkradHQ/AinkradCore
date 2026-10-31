-- Issues and approvals a run created through its MCP token (B-M4): counted in the same statement
-- that checks the cap (`mcp.max_creates_per_run`), so a run cannot exceed it by racing calls.
ALTER TABLE citadel_runs ADD COLUMN mcp_creates INTEGER NOT NULL DEFAULT 0;
