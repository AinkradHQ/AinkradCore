-- Tool calls a run made through its MCP token (S8): counted in the same statement that checks the
-- cap (`mcp.max_calls_per_run`), so a run cannot exceed it by racing calls.
ALTER TABLE citadel_runs ADD COLUMN mcp_calls INTEGER NOT NULL DEFAULT 0;
