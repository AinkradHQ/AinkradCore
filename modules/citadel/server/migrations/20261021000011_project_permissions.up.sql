-- A project's harness permission policy (E3.10), sent with every run of its issues. The
-- default asks before anything outside the allowlist: never full-auto by default.
-- `permission_mode = 'sandboxed'` (act without asking) is only valid with `sandboxed = 1`
-- (runs only on a sandboxed runner), enforced by `set_project_policy`.
ALTER TABLE projects ADD COLUMN permission_mode TEXT NOT NULL DEFAULT 'ask'
    CHECK (permission_mode IN ('ask', 'accept_edits', 'sandboxed'));
ALTER TABLE projects ADD COLUMN allowed_tools TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(allowed_tools) AND json_type(allowed_tools) = 'array');
ALTER TABLE projects ADD COLUMN sandboxed INTEGER NOT NULL DEFAULT 0 CHECK (sandboxed IN (0, 1));
