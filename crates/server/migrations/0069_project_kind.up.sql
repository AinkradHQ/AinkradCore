-- A project's kind (API 111): what it is, so the app shows the right tools. One of `web` (default,
-- also every existing project), `app` (desktop or mobile), `infra` (infrastructure, an OS) or
-- `other` (not software).
ALTER TABLE core_projects ADD COLUMN kind TEXT NOT NULL DEFAULT 'web'
    CHECK (kind IN ('web', 'app', 'infra', 'other'));
