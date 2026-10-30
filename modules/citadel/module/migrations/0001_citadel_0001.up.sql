-- citadel_0001: the squashed Citadel baseline (E2-13.1). Org, work, governance and ledger tables
-- only; the run engine's tables come with the agent-session slice. Run, wake, runner and account
-- references are plain integer columns until then.

CREATE TABLE citadel_companies (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
, kind TEXT NOT NULL DEFAULT 'client'
    CHECK (kind IN ('own', 'client')), color TEXT, description TEXT NOT NULL DEFAULT '', industries TEXT NOT NULL DEFAULT '[]', website TEXT, timezone TEXT, work_start INTEGER, work_end INTEGER, work_days INTEGER, logo_sha256 TEXT);

CREATE TABLE citadel_departments (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), about TEXT NOT NULL DEFAULT '', head_agent_id INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    UNIQUE (company_id, name)
);

CREATE TABLE citadel_teams (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    department_id INTEGER NOT NULL REFERENCES citadel_departments(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE citadel_agents (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id  INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    role        TEXT    NOT NULL,
    org_role    TEXT    NOT NULL DEFAULT 'none' CHECK (org_role IN ('ceo', 'cto', 'none')),

    reports_to  INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    harness     TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model       TEXT    NOT NULL,
    runner_tags TEXT    NOT NULL DEFAULT '[]'
                CHECK (json_valid(runner_tags) AND json_type(runner_tags) = 'array'),
    status      TEXT    NOT NULL
                CHECK (status IN ('active', 'paused', 'pending_approval', 'terminated')),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
, timer_interval_secs INTEGER CHECK (timer_interval_secs > 0), timer_last_fired_at TEXT, figure_version TEXT NOT NULL DEFAULT 'v1'
    CHECK (figure_version <> ''), palette_id TEXT NOT NULL DEFAULT 'neon-tide' CHECK (palette_id <> ''), avatar_sha256 TEXT
    CHECK (avatar_sha256 IS NULL OR length(avatar_sha256) = 64), paused_at TEXT, description TEXT NOT NULL DEFAULT '', effort TEXT CHECK (effort IN ('low', 'medium', 'high')), sandbox TEXT
    CHECK (sandbox IN ('read-only', 'workspace-write', 'full-access')), instructions TEXT NOT NULL DEFAULT '', guidelines TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(guidelines) AND json_type(guidelines) = 'array'), chain_preset_id INTEGER REFERENCES citadel_chain_presets(id) ON DELETE SET NULL);

CREATE TABLE citadel_team_memberships (
    team_id    INTEGER NOT NULL REFERENCES citadel_teams(id) ON DELETE CASCADE,
    agent_id   INTEGER NOT NULL REFERENCES citadel_agents(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    team_role  TEXT    NOT NULL CHECK (team_role IN ('product_owner', 'team_lead', 'member')),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), capacity INTEGER CHECK (capacity >= 0),
    PRIMARY KEY (team_id, agent_id)
);

CREATE TABLE citadel_projects (
    id                INTEGER PRIMARY KEY,
    user_id           INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id        INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,

    team_id           INTEGER REFERENCES citadel_teams(id) ON DELETE SET NULL,
    name              TEXT    NOT NULL,

    key               TEXT    NOT NULL CHECK (key GLOB '[A-Z]*' AND key NOT GLOB '*[^A-Z0-9]*'),
    mode              TEXT    NOT NULL CHECK (mode IN ('scrum', 'kanban')),
    sprint_approval   TEXT    NOT NULL CHECK (sprint_approval IN ('owner', 'product_owner')),

    next_issue_number INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), permission_mode TEXT NOT NULL DEFAULT 'ask'
    CHECK (permission_mode IN ('ask', 'accept_edits', 'sandboxed')), allowed_tools TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(allowed_tools) AND json_type(allowed_tools) = 'array'), sandboxed INTEGER NOT NULL DEFAULT 0 CHECK (sandboxed IN (0, 1)), spec TEXT NOT NULL DEFAULT '', intake INTEGER NOT NULL DEFAULT 0 CHECK (intake IN (0, 1)), requirement_id INTEGER REFERENCES citadel_requirements(id)
    ON DELETE SET NULL, next_epic_number INTEGER NOT NULL DEFAULT 1, icon TEXT, color TEXT, logo_sha256 TEXT, extra_team_ids TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(extra_team_ids) AND json_type(extra_team_ids) = 'array'), runner_tags TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(runner_tags) AND json_type(runner_tags) = 'array'), max_parallel_runs INTEGER CHECK (max_parallel_runs >= 1), run_timeout_secs INTEGER CHECK (run_timeout_secs >= 1), worktree_keep_days INTEGER CHECK (worktree_keep_days >= 0),
    UNIQUE (company_id, key)
);

CREATE TABLE citadel_epics (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id INTEGER NOT NULL REFERENCES citadel_projects(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'open'
               CHECK (status IN ('open', 'in_progress', 'done', 'cancelled')),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
, requirement_id INTEGER REFERENCES citadel_requirements(id)
    ON DELETE SET NULL, number INTEGER CHECK (number > 0), color TEXT, starts_on TEXT, ends_on TEXT);

CREATE TABLE citadel_sprints (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id INTEGER NOT NULL REFERENCES citadel_projects(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    goal       TEXT    NOT NULL DEFAULT '',
    state      TEXT    NOT NULL CHECK (state IN ('planned', 'active', 'closed')),
    starts_on  TEXT,
    ends_on    TEXT,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), committed_points INTEGER CHECK (committed_points >= 0), completed_points INTEGER CHECK (completed_points >= 0), review TEXT CHECK (review IS NULL OR json_valid(review)),
    CHECK (starts_on IS NULL OR ends_on IS NULL OR ends_on >= starts_on)
);

CREATE TABLE citadel_issues (
    id             INTEGER PRIMARY KEY,
    user_id        INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id     INTEGER NOT NULL REFERENCES citadel_projects(id) ON DELETE CASCADE,
    number         INTEGER NOT NULL,
    epic_id        INTEGER REFERENCES citadel_epics(id) ON DELETE SET NULL,

    parent_id      INTEGER REFERENCES citadel_issues(id) ON DELETE CASCADE,
    kind           TEXT    NOT NULL CHECK (kind IN ('story', 'task', 'bug', 'chore', 'spike', 'subtask')),
    title          TEXT    NOT NULL,
    body           TEXT    NOT NULL DEFAULT '',
    state          TEXT    NOT NULL CHECK (state IN
                   ('backlog', 'todo', 'in_progress', 'in_review', 'blocked', 'done', 'cancelled')),

    owner_agent_id INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    owner_user_id  INTEGER REFERENCES users(id),


    next_agent_id  INTEGER REFERENCES citadel_agents(id),
    next_user_id   INTEGER REFERENCES users(id),
    next_at        TEXT,
    points         INTEGER CHECK (points >= 0),
    sprint_id      INTEGER REFERENCES citadel_sprints(id) ON DELETE SET NULL,
    rank           REAL    NOT NULL,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), checkout_run_id INTEGER, checked_out_at TEXT
    CHECK ((checkout_run_id IS NULL) = (checked_out_at IS NULL)), cross_department INTEGER NOT NULL DEFAULT 0
    CHECK (cross_department IN (0, 1)), updated_at TEXT, requirement_id INTEGER REFERENCES citadel_requirements(id)
    ON DELETE SET NULL, priority INTEGER NOT NULL DEFAULT 0 CHECK (priority IN (0, 1)), branch TEXT, priority_level TEXT NOT NULL DEFAULT 'none'
    CHECK (priority_level IN ('none', 'low', 'medium', 'high', 'urgent')), criteria TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(criteria)),
    UNIQUE (project_id, number),
    CHECK ((kind = 'subtask') = (parent_id IS NOT NULL)),
    CHECK (owner_agent_id IS NULL OR owner_user_id IS NULL),
    CHECK ((next_agent_id IS NOT NULL) + (next_user_id IS NOT NULL) + (next_at IS NOT NULL) <= 1),
    CHECK (state IN ('done', 'cancelled')
           OR next_agent_id IS NOT NULL OR next_user_id IS NOT NULL OR next_at IS NOT NULL)
);

CREATE TABLE citadel_labels (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id INTEGER NOT NULL REFERENCES citadel_projects(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (project_id, name)
);

CREATE TABLE citadel_issue_labels (
    issue_id   INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    label_id   INTEGER NOT NULL REFERENCES citadel_labels(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (issue_id, label_id)
);

CREATE TABLE citadel_blocker_links (
    blocker_id INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (blocker_id, blocked_id),
    CHECK (blocker_id <> blocked_id)
);

CREATE TABLE citadel_cost_events (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    run_id          INTEGER NOT NULL,
    agent_id        INTEGER NOT NULL REFERENCES citadel_agents(id) ON DELETE CASCADE,
    issue_id        INTEGER REFERENCES citadel_issues(id) ON DELETE SET NULL,
    input_tokens    INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens   INTEGER NOT NULL CHECK (output_tokens >= 0),
    cache_tokens    INTEGER NOT NULL CHECK (cache_tokens >= 0),
    cost_usd_micros INTEGER CHECK (cost_usd_micros >= 0),
    priced          INTEGER NOT NULL CHECK (priced IN (0, 1)),
    idempotency_key TEXT    NOT NULL UNIQUE,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), price_id INTEGER REFERENCES citadel_prices(id), billing TEXT NOT NULL DEFAULT 'metered'
    CHECK (billing IN ('metered', 'subscription')), account_id INTEGER,
    CHECK (priced = (cost_usd_micros IS NOT NULL))
);

CREATE TABLE citadel_skills (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id    INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    version       INTEGER NOT NULL CHECK (version >= 1),
    body          TEXT    NOT NULL,
    attach_scope  TEXT    NOT NULL
                  CHECK (attach_scope IN ('company', 'department', 'role', 'project')),
    department_id INTEGER REFERENCES citadel_departments(id) ON DELETE CASCADE,
    role          TEXT,
    project_id    INTEGER REFERENCES citadel_projects(id) ON DELETE CASCADE,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((department_id IS NOT NULL) = (attach_scope = 'department')),
    CHECK ((role IS NOT NULL) = (attach_scope = 'role')),
    CHECK ((project_id IS NOT NULL) = (attach_scope = 'project')),
    UNIQUE (company_id, name, version)
);

CREATE TABLE citadel_comments (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    issue_id        INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    author_agent_id INTEGER REFERENCES citadel_agents(id),
    author_user_id  INTEGER REFERENCES users(id),
    body            TEXT    NOT NULL,

    run_id          INTEGER,
    idempotency_key TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((author_agent_id IS NULL) <> (author_user_id IS NULL)),
    UNIQUE (issue_id, idempotency_key)
);

CREATE TABLE citadel_issue_state_history (
    id         INTEGER PRIMARY KEY,
    issue_id   INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,

    from_state TEXT,
    to_state   TEXT    NOT NULL,
    at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE citadel_wip_limits (
    project_id INTEGER NOT NULL REFERENCES citadel_projects(id) ON DELETE CASCADE,
    state      TEXT    NOT NULL
               CHECK (state IN ('backlog', 'todo', 'in_progress', 'in_review', 'blocked')),
    max_issues INTEGER NOT NULL CHECK (max_issues > 0),
    PRIMARY KEY (project_id, state)
);

CREATE TABLE citadel_prices (
    id                     INTEGER PRIMARY KEY,
    harness                TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model                  TEXT    NOT NULL CHECK (model <> ''),
    version                INTEGER NOT NULL CHECK (version >= 1),

    input_micros_per_mtok  INTEGER NOT NULL CHECK (input_micros_per_mtok >= 0),
    output_micros_per_mtok INTEGER NOT NULL CHECK (output_micros_per_mtok >= 0),
    cache_micros_per_mtok  INTEGER NOT NULL CHECK (cache_micros_per_mtok >= 0),
    created_at             TEXT    NOT NULL,
    UNIQUE (harness, model, version)
);

CREATE TABLE citadel_harness_billing (
    harness TEXT PRIMARY KEY CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    billing TEXT NOT NULL CHECK (billing IN ('metered', 'subscription'))
);

CREATE TABLE citadel_project_linear (
    project_id INTEGER PRIMARY KEY REFERENCES citadel_projects(id) ON DELETE CASCADE,
    team_id    TEXT    NOT NULL,
    api_url    TEXT    NOT NULL,
    token_file TEXT    NOT NULL,
    cursor     TEXT
);

CREATE TABLE citadel_linear_issues (
    issue_id   INTEGER PRIMARY KEY REFERENCES citadel_issues(id) ON DELETE CASCADE,
    linear_id  TEXT    NOT NULL UNIQUE,
    identifier TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,

    state      TEXT    NOT NULL,

    assignee   TEXT,
    synced_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE citadel_agent_fallbacks (
    agent_id INTEGER NOT NULL REFERENCES citadel_agents(id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 1),
    harness  TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model    TEXT    NOT NULL CHECK (model <> ''),
    PRIMARY KEY (agent_id, position)
);

CREATE TABLE citadel_agent_tiers (
    agent_id INTEGER NOT NULL REFERENCES citadel_agents(id) ON DELETE CASCADE,
    tier     TEXT    NOT NULL CHECK (tier IN ('small', 'large')),
    harness  TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model    TEXT    NOT NULL CHECK (model <> ''),
    PRIMARY KEY (agent_id, tier)
);

CREATE TABLE citadel_tier_rules (
    project_id INTEGER NOT NULL REFERENCES citadel_projects(id) ON DELETE CASCADE,
    rule       TEXT    NOT NULL CHECK (rule GLOB 'label:?*' OR rule GLOB 'kind:?*'),
    tier       TEXT    NOT NULL CHECK (tier IN ('small', 'standard', 'large')),
    PRIMARY KEY (project_id, rule)
);

CREATE TABLE citadel_project_profiles (
    project_id INTEGER PRIMARY KEY REFERENCES citadel_projects(id) ON DELETE CASCADE,
    profile    TEXT    NOT NULL CHECK (json_valid(profile) AND json_type(profile) = 'object'),
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE citadel_project_repos (
    id               INTEGER PRIMARY KEY,
    user_id          INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id       INTEGER NOT NULL REFERENCES citadel_projects(id) ON DELETE CASCADE,

    name             TEXT    NOT NULL CHECK (name <> '' AND name NOT GLOB '*[^A-Za-z0-9._-]*'
                                             AND name NOT GLOB '.*'),
    url              TEXT    NOT NULL CHECK (url <> ''),
    default_branch   TEXT    NOT NULL DEFAULT 'main' CHECK (default_branch <> ''),
    position         INTEGER NOT NULL DEFAULT 0,
    is_primary       INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    forge_kind       TEXT    CHECK (forge_kind IN ('github', 'gitlab')),
    forge_api_url    TEXT,
    forge_repo       TEXT,
    forge_token_file TEXT,
    build_cmd        TEXT    NOT NULL DEFAULT '',
    test_cmd         TEXT    NOT NULL DEFAULT '',
    lint_cmd         TEXT    NOT NULL DEFAULT '',
    format_cmd       TEXT    NOT NULL DEFAULT '',
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), stack TEXT NOT NULL DEFAULT '',
    CHECK ((forge_kind IS NULL) = (forge_api_url IS NULL)
       AND (forge_kind IS NULL) = (forge_repo IS NULL)
       AND (forge_kind IS NULL) = (forge_token_file IS NULL)),
    UNIQUE (project_id, name),
    UNIQUE (project_id, url)
);

CREATE TABLE citadel_issue_prs (
    issue_id        INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    repo_id         INTEGER NOT NULL REFERENCES citadel_project_repos(id) ON DELETE CASCADE,
    state           TEXT    NOT NULL DEFAULT 'requested'
                    CHECK (state IN ('requested', 'open', 'merging', 'merged', 'closed')),
    number          INTEGER,
    url             TEXT,
    title           TEXT    NOT NULL,
    body            TEXT    NOT NULL,
    head            TEXT    NOT NULL,
    base            TEXT    NOT NULL,
    head_sha        TEXT,
    checks          TEXT    NOT NULL DEFAULT 'none'
                    CHECK (checks IN ('none', 'pending', 'success', 'failure')),
    author_agent_id INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    last_error      TEXT,
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), checks_note TEXT, unpushed_at TEXT, push_held TEXT, pushed_sha TEXT,
    PRIMARY KEY (issue_id, repo_id),
    CHECK ((state = 'requested') = (number IS NULL))
);

CREATE TABLE citadel_issue_repos (
    issue_id              INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    repo_id               INTEGER NOT NULL REFERENCES citadel_project_repos(id) ON DELETE CASCADE,
    state                 TEXT    NOT NULL DEFAULT 'approved'
                          CHECK (state IN ('requested', 'approved', 'rejected')),
    requested_by_agent_id INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,

    reason                TEXT,
    PRIMARY KEY (issue_id, repo_id)
);

CREATE TABLE citadel_requirements (
    id                   INTEGER PRIMARY KEY,
    company_id           INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    number               INTEGER NOT NULL CHECK (number > 0),
    title                TEXT    NOT NULL CHECK (title <> ''),
    body                 TEXT    NOT NULL DEFAULT '',
    requested_by_user_id INTEGER NOT NULL REFERENCES users(id),

    intake_issue_id      INTEGER REFERENCES citadel_issues(id) ON DELETE SET NULL,
    owner_agent_id       INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    owner_issue_id       INTEGER REFERENCES citadel_issues(id) ON DELETE SET NULL,
    state                TEXT    NOT NULL DEFAULT 'planning'
                         CHECK (state IN ('planning', 'plan_review', 'in_progress', 'done',
                                          'cancelled')),

    plan_version         INTEGER NOT NULL DEFAULT 0 CHECK (plan_version >= 0),
    created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), project_id INTEGER REFERENCES citadel_projects(id) ON DELETE SET NULL, priority_level TEXT NOT NULL DEFAULT 'none'
    CHECK (priority_level IN ('none', 'low', 'medium', 'high', 'urgent')), criteria TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(criteria)), paused_at TEXT,
    UNIQUE (company_id, number)
);

CREATE TABLE citadel_requirement_plans (
    requirement_id INTEGER NOT NULL REFERENCES citadel_requirements(id) ON DELETE CASCADE,
    version        INTEGER NOT NULL CHECK (version > 0),

    tasks          TEXT    NOT NULL CHECK (json_valid(tasks) AND json_type(tasks) = 'array'),
    approval_id    INTEGER,

    approved_by    TEXT    NOT NULL CHECK (approved_by IN ('owner', 'product_owner')),
    approved_at    TEXT    NOT NULL,
    PRIMARY KEY (requirement_id, version)
);

CREATE TABLE citadel_questions (
    id                  INTEGER PRIMARY KEY,

    requirement_id      INTEGER REFERENCES citadel_requirements(id) ON DELETE CASCADE,
    issue_id            INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    agent_id            INTEGER NOT NULL REFERENCES citadel_agents(id),
    run_id              INTEGER,
    question            TEXT    NOT NULL CHECK (question <> ''),
    options             TEXT    NOT NULL DEFAULT '[]'
                        CHECK (json_valid(options) AND json_type(options) = 'array'),
    state               TEXT    NOT NULL DEFAULT 'open'
                        CHECK (state IN ('open', 'answered', 'cancelled')),
    answer              TEXT,
    answered_by_user_id INTEGER REFERENCES users(id),

    answered_in         TEXT    CHECK (answered_in IN ('requirement', 'issue')),
    question_comment_id INTEGER REFERENCES citadel_comments(id) ON DELETE SET NULL,
    answer_comment_id   INTEGER REFERENCES citadel_comments(id) ON DELETE SET NULL,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    answered_at         TEXT,
    CHECK ((state = 'answered') = (answer IS NOT NULL AND answered_at IS NOT NULL))
);

CREATE TABLE citadel_artifacts (
    id             INTEGER PRIMARY KEY,
    company_id     INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    issue_id       INTEGER REFERENCES citadel_issues(id) ON DELETE SET NULL,
    requirement_id INTEGER REFERENCES citadel_requirements(id) ON DELETE SET NULL,
    run_id         INTEGER,
    agent_id       INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    name           TEXT    NOT NULL CHECK (name <> '' AND length(name) <= 200),
    kind           TEXT    NOT NULL CHECK (kind IN ('report', 'file', 'screenshot', 'other')),
    mime           TEXT    NOT NULL CHECK (mime <> ''),
    size           INTEGER NOT NULL CHECK (size >= 0),
    sha256         TEXT    NOT NULL CHECK (length(sha256) = 64),
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
, redactions INTEGER NOT NULL DEFAULT 0 CHECK (redactions >= 0), unscanned INTEGER NOT NULL DEFAULT 0 CHECK (unscanned IN (0, 1)));

CREATE TABLE citadel_artifact_reads (
    id         INTEGER PRIMARY KEY,
    run_id     INTEGER NOT NULL,
    path       TEXT    NOT NULL CHECK (path <> ''),
    max_bytes  INTEGER NOT NULL CHECK (max_bytes > 0),
    state      TEXT    NOT NULL DEFAULT 'pending'
               CHECK (state IN ('pending', 'sent', 'done', 'failed')),
    error      TEXT,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE citadel_plan_applies (
    id             INTEGER PRIMARY KEY,
    requirement_id INTEGER NOT NULL REFERENCES citadel_requirements(id) ON DELETE CASCADE,
    client_key     TEXT    NOT NULL CHECK (client_key <> '' AND length(client_key) <= 200),
    agent_id       INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    result         TEXT    NOT NULL,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (requirement_id, client_key)
);

CREATE TABLE citadel_avatar_palettes (
    id       TEXT    PRIMARY KEY CHECK (id <> ''),
    name     TEXT    NOT NULL UNIQUE CHECK (name <> ''),
    position INTEGER NOT NULL UNIQUE CHECK (position > 0)
);

CREATE TABLE citadel_issue_allow_rules (
    id          INTEGER PRIMARY KEY,
    issue_id    INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    rule        TEXT    NOT NULL CHECK (rule <> ''),
    approval_id INTEGER REFERENCES citadel_approvals(id) ON DELETE SET NULL,
    created_at  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL
);

CREATE TABLE citadel_knowledge_entries (
    id                   INTEGER PRIMARY KEY,
    user_id              INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    project_id           INTEGER NOT NULL REFERENCES citadel_projects(id) ON DELETE CASCADE,
    kind                 TEXT    NOT NULL CHECK (kind IN ('decision', 'landmine', 'state', 'retro')),
    title                TEXT    NOT NULL,
    body                 TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'proposed'
                         CHECK (status IN ('proposed', 'accepted', 'rejected', 'retired')),


    target               TEXT    CHECK (target IS NULL OR (target = 'spec' AND kind = 'state')
                                        OR target GLOB 'profile.?*'),

    proposed_by_agent_id INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    decided_by_user_id   INTEGER REFERENCES users(id),
    decided_by_agent_id  INTEGER REFERENCES citadel_agents(id),
    reason               TEXT,
    rationale            TEXT,


    retired_reason       TEXT,
    supersedes_id        INTEGER REFERENCES citadel_knowledge_entries(id) ON DELETE SET NULL,
    created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (decided_by_user_id IS NULL OR decided_by_agent_id IS NULL),
    CHECK ((status = 'proposed') = (decided_by_user_id IS NULL AND decided_by_agent_id IS NULL))
);

CREATE TABLE citadel_sprint_retro_items (
    entry_id  INTEGER PRIMARY KEY REFERENCES citadel_knowledge_entries(id) ON DELETE CASCADE,
    sprint_id INTEGER NOT NULL REFERENCES citadel_sprints(id) ON DELETE CASCADE
);

CREATE TABLE citadel_approvals (
    id                      INTEGER PRIMARY KEY,
    user_id                 INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    company_id              INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    kind                    TEXT    NOT NULL CHECK (kind IN ('sprint_commit', 'pr_merge',
                            'budget_overrun', 'hire_agent', 'permission_escalation',
                            'plan_approval', 'workflow_push')),
    issue_id                INTEGER REFERENCES citadel_issues(id) ON DELETE SET NULL,
    sprint_id               INTEGER REFERENCES citadel_sprints(id) ON DELETE SET NULL,
    agent_id                INTEGER REFERENCES citadel_agents(id) ON DELETE SET NULL,
    requirement_id          INTEGER REFERENCES citadel_requirements(id) ON DELETE SET NULL,
    requested_by_agent_id   INTEGER NOT NULL REFERENCES citadel_agents(id),
    status                  TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    decided_by_user_id      INTEGER REFERENCES users(id),
    reply                   TEXT,
    payload                 TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),
    expires_at              TEXT,
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), decided_at TEXT,
    CHECK ((status IN ('approved', 'rejected')) = (decided_by_user_id IS NOT NULL))
);

CREATE TABLE citadel_budgets (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    scope           TEXT    NOT NULL
                    CHECK (scope IN ('company', 'department', 'project', 'agent', 'sprint', 'issue')),
    company_id      INTEGER REFERENCES citadel_companies(id) ON DELETE CASCADE,
    department_id   INTEGER REFERENCES citadel_departments(id) ON DELETE CASCADE,
    project_id      INTEGER REFERENCES citadel_projects(id) ON DELETE CASCADE,
    agent_id        INTEGER REFERENCES citadel_agents(id) ON DELETE CASCADE,
    sprint_id       INTEGER REFERENCES citadel_sprints(id) ON DELETE CASCADE,
    issue_id        INTEGER REFERENCES citadel_issues(id) ON DELETE CASCADE,
    scope_id        INTEGER GENERATED ALWAYS AS
                    (coalesce(company_id, department_id, project_id, agent_id, sprint_id,
                              issue_id)) VIRTUAL,
    period          TEXT    NOT NULL CHECK (period IN ('day', 'week', 'month', 'total')),
    token_cap       INTEGER NOT NULL CHECK (token_cap >= 0),
    usd_cap_micros  INTEGER CHECK (usd_cap_micros >= 0),
    warn_at_percent INTEGER NOT NULL DEFAULT 80 CHECK (warn_at_percent BETWEEN 1 AND 100),
    hard_stop       INTEGER NOT NULL DEFAULT 1 CHECK (hard_stop IN (0, 1)),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((company_id IS NOT NULL) = (scope = 'company')),
    CHECK ((department_id IS NOT NULL) = (scope = 'department')),
    CHECK ((project_id IS NOT NULL) = (scope = 'project')),
    CHECK ((agent_id IS NOT NULL) = (scope = 'agent')),
    CHECK ((sprint_id IS NOT NULL) = (scope = 'sprint')),
    CHECK ((issue_id IS NOT NULL) = (scope = 'issue')),
    UNIQUE (scope, scope_id, period)
);

CREATE TABLE citadel_budget_spend (
    budget_id         INTEGER NOT NULL REFERENCES citadel_budgets(id) ON DELETE CASCADE,
    period_key        TEXT    NOT NULL CHECK (period_key <> ''),
    tokens            INTEGER NOT NULL DEFAULT 0 CHECK (tokens >= 0),
    raised            INTEGER NOT NULL DEFAULT 0 CHECK (raised >= 0),
    warned_at         TEXT,
    usd_micros        INTEGER NOT NULL DEFAULT 0 CHECK (usd_micros >= 0),
    raised_usd_micros INTEGER NOT NULL DEFAULT 0 CHECK (raised_usd_micros >= 0),
    PRIMARY KEY (budget_id, period_key)
) WITHOUT ROWID;

CREATE TABLE citadel_chain_presets (
    id          INTEGER PRIMARY KEY,
    company_id  INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL CHECK (name <> ''),
    color       TEXT    CHECK (color IS NULL OR color GLOB '#[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]'),
    description TEXT    NOT NULL DEFAULT '',
    is_default  INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (company_id, name)
);

CREATE TABLE citadel_chain_preset_entries (
    preset_id  INTEGER NOT NULL REFERENCES citadel_chain_presets(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL CHECK (position >= 1),
    harness    TEXT    NOT NULL CHECK (harness IN ('claude', 'codex', 'opencode', 'agy')),
    model      TEXT    NOT NULL CHECK (model <> ''),
    account_id INTEGER,
    PRIMARY KEY (preset_id, position)
);

CREATE TABLE citadel_roles (
    id            INTEGER PRIMARY KEY,
    company_id    INTEGER NOT NULL REFERENCES citadel_companies(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL CHECK (name <> ''),
    purpose       TEXT    NOT NULL DEFAULT '',
    icon          TEXT    NOT NULL DEFAULT '',
    harness       TEXT    CHECK (harness IS NULL OR harness IN ('claude', 'codex', 'opencode', 'agy')),
    model         TEXT    CHECK (model IS NULL OR model <> ''),
    budget_tokens INTEGER CHECK (budget_tokens IS NULL OR budget_tokens >= 0),
    citadel_skills        TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(citadel_skills)),
    instructions  TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (company_id, name)
);

CREATE TABLE citadel_issue_pushed_heads (
    issue_id INTEGER NOT NULL REFERENCES citadel_issues(id) ON DELETE CASCADE,
    repo_id  INTEGER NOT NULL REFERENCES citadel_project_repos(id) ON DELETE CASCADE,
    sha      TEXT    NOT NULL,
    PRIMARY KEY (issue_id, repo_id)
);

CREATE INDEX citadel_teams_department ON citadel_teams (department_id);

CREATE INDEX citadel_agents_company ON citadel_agents (company_id);

CREATE INDEX citadel_agents_reports_to ON citadel_agents (reports_to);

CREATE UNIQUE INDEX citadel_agents_one_per_org_role ON citadel_agents (company_id, org_role)
    WHERE org_role <> 'none';

CREATE INDEX citadel_team_memberships_agent ON citadel_team_memberships (agent_id);

CREATE UNIQUE INDEX citadel_team_memberships_one_per_lead_role ON citadel_team_memberships (team_id, team_role)
    WHERE team_role <> 'member';

CREATE INDEX citadel_projects_team ON citadel_projects (team_id);

CREATE INDEX citadel_epics_project ON citadel_epics (project_id);

CREATE INDEX citadel_sprints_project ON citadel_sprints (project_id);

CREATE UNIQUE INDEX citadel_sprints_one_active ON citadel_sprints (project_id) WHERE state = 'active';

CREATE INDEX citadel_issues_backlog ON citadel_issues (project_id, rank);

CREATE INDEX citadel_issues_epic ON citadel_issues (epic_id);

CREATE INDEX citadel_issues_parent ON citadel_issues (parent_id);

CREATE INDEX citadel_issues_sprint ON citadel_issues (sprint_id);

CREATE INDEX citadel_issues_owner_agent ON citadel_issues (owner_agent_id);

CREATE INDEX citadel_issues_next_agent ON citadel_issues (next_agent_id);

CREATE INDEX citadel_issue_labels_label ON citadel_issue_labels (label_id);

CREATE INDEX citadel_blocker_links_blocked ON citadel_blocker_links (blocked_id);

CREATE INDEX citadel_cost_events_run ON citadel_cost_events (run_id);

CREATE INDEX citadel_cost_events_agent ON citadel_cost_events (agent_id);

CREATE INDEX citadel_cost_events_issue ON citadel_cost_events (issue_id);

CREATE INDEX citadel_skills_department ON citadel_skills (department_id);

CREATE INDEX citadel_skills_project ON citadel_skills (project_id);

CREATE INDEX citadel_comments_author_agent ON citadel_comments (author_agent_id);

CREATE INDEX citadel_comments_run ON citadel_comments (run_id);

CREATE INDEX citadel_issue_state_history_issue ON citadel_issue_state_history (issue_id, at);

CREATE UNIQUE INDEX citadel_projects_one_intake ON citadel_projects (company_id) WHERE intake = 1;

CREATE INDEX citadel_cost_events_price ON citadel_cost_events (price_id);

CREATE INDEX citadel_cost_events_account ON citadel_cost_events (account_id, created_at);

CREATE UNIQUE INDEX citadel_project_repos_one_primary ON citadel_project_repos (project_id) WHERE is_primary = 1;

CREATE INDEX citadel_issue_prs_state ON citadel_issue_prs (state);

CREATE INDEX citadel_issue_prs_repo ON citadel_issue_prs (repo_id);

CREATE INDEX citadel_issue_repos_repo ON citadel_issue_repos (repo_id);

CREATE INDEX citadel_requirements_intake ON citadel_requirements (intake_issue_id);

CREATE INDEX citadel_projects_requirement ON citadel_projects (requirement_id);

CREATE INDEX citadel_epics_requirement ON citadel_epics (requirement_id);

CREATE INDEX citadel_issues_requirement ON citadel_issues (requirement_id);

CREATE INDEX citadel_questions_requirement ON citadel_questions (requirement_id, state);

CREATE INDEX citadel_questions_issue ON citadel_questions (issue_id, state);

CREATE INDEX citadel_questions_agent ON citadel_questions (agent_id);

CREATE INDEX citadel_artifacts_company ON citadel_artifacts (company_id, id);

CREATE INDEX citadel_artifacts_requirement ON citadel_artifacts (requirement_id);

CREATE INDEX citadel_artifacts_issue ON citadel_artifacts (issue_id);

CREATE INDEX citadel_artifacts_agent ON citadel_artifacts (agent_id);

CREATE INDEX citadel_artifacts_sha ON citadel_artifacts (company_id, sha256);

CREATE INDEX citadel_artifact_reads_open ON citadel_artifact_reads (run_id) WHERE state IN ('pending', 'sent');

CREATE INDEX citadel_issue_allow_rules_issue ON citadel_issue_allow_rules (issue_id);

CREATE UNIQUE INDEX citadel_epics_number ON citadel_epics (project_id, number);

CREATE INDEX citadel_knowledge_entries_project ON citadel_knowledge_entries (project_id, status);

CREATE INDEX citadel_knowledge_entries_proposed_by ON citadel_knowledge_entries (proposed_by_agent_id);

CREATE INDEX citadel_knowledge_entries_decided_by ON citadel_knowledge_entries (decided_by_agent_id);

CREATE INDEX citadel_knowledge_entries_supersedes ON citadel_knowledge_entries (supersedes_id);

CREATE INDEX citadel_sprint_retro_items_sprint ON citadel_sprint_retro_items (sprint_id);

CREATE INDEX citadel_approvals_pending ON citadel_approvals (company_id) WHERE status = 'pending';

CREATE INDEX citadel_approvals_requested_by ON citadel_approvals (requested_by_agent_id);

CREATE INDEX citadel_approvals_issue ON citadel_approvals (issue_id);

CREATE INDEX citadel_approvals_sprint ON citadel_approvals (sprint_id);

CREATE INDEX citadel_approvals_agent ON citadel_approvals (agent_id);

CREATE INDEX citadel_approvals_requirement ON citadel_approvals (requirement_id);

CREATE INDEX citadel_approvals_expiring ON citadel_approvals (expires_at) WHERE status = 'pending';

CREATE UNIQUE INDEX citadel_chain_presets_default ON citadel_chain_presets (company_id) WHERE is_default = 1;

CREATE INDEX citadel_agents_chain_preset ON citadel_agents (chain_preset_id);

CREATE TRIGGER citadel_projects_team_same_company_insert BEFORE INSERT ON citadel_projects
WHEN NEW.team_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'team belongs to another company')
    WHERE (SELECT d.company_id FROM citadel_teams t JOIN citadel_departments d ON d.id = t.department_id
           WHERE t.id = NEW.team_id) <> NEW.company_id;
END;

CREATE TRIGGER citadel_projects_team_same_company_update BEFORE UPDATE OF team_id, company_id ON citadel_projects
WHEN NEW.team_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'team belongs to another company')
    WHERE (SELECT d.company_id FROM citadel_teams t JOIN citadel_departments d ON d.id = t.department_id
           WHERE t.id = NEW.team_id) <> NEW.company_id;
END;

CREATE TRIGGER citadel_issues_same_project_insert BEFORE INSERT ON citadel_issues
BEGIN
    SELECT RAISE(ABORT, 'epic belongs to another project')
    WHERE (SELECT project_id FROM citadel_epics WHERE id = NEW.epic_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'sprint belongs to another project')
    WHERE (SELECT project_id FROM citadel_sprints WHERE id = NEW.sprint_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'parent belongs to another project')
    WHERE (SELECT project_id FROM citadel_issues WHERE id = NEW.parent_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'a subtask cannot have subtasks')
    WHERE (SELECT kind FROM citadel_issues WHERE id = NEW.parent_id) = 'subtask';
END;

CREATE TRIGGER citadel_issues_same_project_update
BEFORE UPDATE OF project_id, epic_id, sprint_id, parent_id ON citadel_issues
BEGIN
    SELECT RAISE(ABORT, 'epic belongs to another project')
    WHERE (SELECT project_id FROM citadel_epics WHERE id = NEW.epic_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'sprint belongs to another project')
    WHERE (SELECT project_id FROM citadel_sprints WHERE id = NEW.sprint_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'parent belongs to another project')
    WHERE (SELECT project_id FROM citadel_issues WHERE id = NEW.parent_id) <> NEW.project_id;
    SELECT RAISE(ABORT, 'a subtask cannot have subtasks')
    WHERE (SELECT kind FROM citadel_issues WHERE id = NEW.parent_id) = 'subtask';
    SELECT RAISE(ABORT, 'an issue cannot be its own parent') WHERE NEW.parent_id = NEW.id;
    SELECT RAISE(ABORT, 'an issue with subtasks cannot become a subtask')
    WHERE NEW.parent_id IS NOT NULL AND EXISTS (SELECT 1 FROM citadel_issues WHERE parent_id = NEW.id);
END;

CREATE TRIGGER citadel_issue_labels_same_project BEFORE INSERT ON citadel_issue_labels
BEGIN
    SELECT RAISE(ABORT, 'label belongs to another project')
    WHERE (SELECT project_id FROM citadel_labels WHERE id = NEW.label_id)
       <> (SELECT project_id FROM citadel_issues WHERE id = NEW.issue_id);
END;

CREATE TRIGGER citadel_skills_same_company_insert BEFORE INSERT ON citadel_skills
BEGIN
    SELECT RAISE(ABORT, 'department belongs to another company')
    WHERE (SELECT company_id FROM citadel_departments WHERE id = NEW.department_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'project belongs to another company')
    WHERE (SELECT company_id FROM citadel_projects WHERE id = NEW.project_id) <> NEW.company_id;
END;

CREATE TRIGGER citadel_skills_same_company_update
BEFORE UPDATE OF company_id, department_id, project_id ON citadel_skills
BEGIN
    SELECT RAISE(ABORT, 'department belongs to another company')
    WHERE (SELECT company_id FROM citadel_departments WHERE id = NEW.department_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'project belongs to another company')
    WHERE (SELECT company_id FROM citadel_projects WHERE id = NEW.project_id) <> NEW.company_id;
END;

CREATE TRIGGER citadel_issues_history_insert AFTER INSERT ON citadel_issues
BEGIN
    INSERT INTO citadel_issue_state_history (issue_id, to_state, at)
    VALUES (NEW.id, NEW.state, NEW.created_at);
END;

CREATE TRIGGER citadel_issues_history_update AFTER UPDATE OF state ON citadel_issues
WHEN NEW.state <> OLD.state
BEGIN
    INSERT INTO citadel_issue_state_history (issue_id, from_state, to_state)
    VALUES (NEW.id, OLD.state, NEW.state);
END;

CREATE TRIGGER citadel_agents_manager_insert BEFORE INSERT ON citadel_agents
WHEN NEW.reports_to IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'manager belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.reports_to) <> NEW.company_id;
    SELECT RAISE(ABORT, 'an agent cannot report to itself') WHERE NEW.reports_to = NEW.id;
END;

CREATE TRIGGER citadel_agents_manager_update BEFORE UPDATE OF reports_to ON citadel_agents
WHEN NEW.reports_to IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'manager belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.reports_to) <> NEW.company_id;
    SELECT RAISE(ABORT, 'reporting cycle')
    WHERE NEW.id IN (WITH RECURSIVE citadel_chain(id) AS (
        SELECT NEW.reports_to
        UNION SELECT a.reports_to FROM citadel_agents a JOIN citadel_chain c ON a.id = c.id
        WHERE a.reports_to IS NOT NULL) SELECT id FROM citadel_chain);
END;

CREATE TRIGGER citadel_agents_company_fixed BEFORE UPDATE OF company_id ON citadel_agents
WHEN NEW.company_id <> OLD.company_id
BEGIN
    SELECT RAISE(ABORT, 'an agent cannot move to another company');
END;

CREATE TRIGGER citadel_departments_company_fixed BEFORE UPDATE OF company_id ON citadel_departments
WHEN NEW.company_id <> OLD.company_id
BEGIN
    SELECT RAISE(ABORT, 'a department cannot move to another company');
END;

CREATE TRIGGER citadel_teams_company_fixed BEFORE UPDATE OF department_id ON citadel_teams
BEGIN
    SELECT RAISE(ABORT, 'a team cannot move to another company')
    WHERE (SELECT company_id FROM citadel_departments WHERE id = NEW.department_id)
       <> (SELECT company_id FROM citadel_departments WHERE id = OLD.department_id);
END;

CREATE TRIGGER citadel_team_memberships_same_company_insert BEFORE INSERT ON citadel_team_memberships
BEGIN
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.agent_id)
       <> (SELECT d.company_id FROM citadel_teams t JOIN citadel_departments d ON d.id = t.department_id
           WHERE t.id = NEW.team_id);
END;

CREATE TRIGGER citadel_team_memberships_same_company_update
BEFORE UPDATE OF team_id, agent_id ON citadel_team_memberships
BEGIN
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.agent_id)
       <> (SELECT d.company_id FROM citadel_teams t JOIN citadel_departments d ON d.id = t.department_id
           WHERE t.id = NEW.team_id);
END;

CREATE TRIGGER citadel_issues_agents_same_company_insert BEFORE INSERT ON citadel_issues
WHEN NEW.owner_agent_id IS NOT NULL OR NEW.next_agent_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'owner belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.owner_agent_id)
       <> (SELECT company_id FROM citadel_projects WHERE id = NEW.project_id);
    SELECT RAISE(ABORT, 'next actor belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.next_agent_id)
       <> (SELECT company_id FROM citadel_projects WHERE id = NEW.project_id);
END;

CREATE TRIGGER citadel_issues_agents_same_company_update
BEFORE UPDATE OF owner_agent_id, next_agent_id, project_id ON citadel_issues
WHEN NEW.owner_agent_id IS NOT NULL OR NEW.next_agent_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'owner belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.owner_agent_id)
       <> (SELECT company_id FROM citadel_projects WHERE id = NEW.project_id);
    SELECT RAISE(ABORT, 'next actor belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.next_agent_id)
       <> (SELECT company_id FROM citadel_projects WHERE id = NEW.project_id);
END;

CREATE TRIGGER citadel_issues_updated_at AFTER UPDATE OF title, body, state, next_agent_id, next_user_id
ON citadel_issues
BEGIN
    UPDATE citadel_issues SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER citadel_issue_prs_same_project BEFORE INSERT ON citadel_issue_prs
BEGIN
    SELECT RAISE(ABORT, 'repo belongs to another project')
    WHERE (SELECT project_id FROM citadel_project_repos WHERE id = NEW.repo_id)
       <> (SELECT project_id FROM citadel_issues WHERE id = NEW.issue_id);
END;

CREATE TRIGGER citadel_issue_repos_same_project BEFORE INSERT ON citadel_issue_repos
BEGIN
    SELECT RAISE(ABORT, 'repo belongs to another project')
    WHERE (SELECT project_id FROM citadel_project_repos WHERE id = NEW.repo_id)
       <> (SELECT project_id FROM citadel_issues WHERE id = NEW.issue_id);
END;

CREATE TRIGGER citadel_epics_number AFTER INSERT ON citadel_epics
BEGIN
    UPDATE citadel_epics SET number = (SELECT next_epic_number FROM citadel_projects WHERE id = NEW.project_id)
    WHERE id = NEW.id;
    UPDATE citadel_projects SET next_epic_number = next_epic_number + 1 WHERE id = NEW.project_id;
END;

CREATE TRIGGER citadel_knowledge_entries_same_company BEFORE INSERT ON citadel_knowledge_entries
BEGIN
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.proposed_by_agent_id)
       <> (SELECT company_id FROM citadel_projects WHERE id = NEW.project_id);
END;

CREATE TRIGGER citadel_knowledge_entries_decider_same_company
BEFORE UPDATE OF decided_by_agent_id ON citadel_knowledge_entries
BEGIN
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.decided_by_agent_id)
       <> (SELECT company_id FROM citadel_projects WHERE id = NEW.project_id);
END;

CREATE TRIGGER citadel_sprint_retro_items_same_project BEFORE INSERT ON citadel_sprint_retro_items
BEGIN
    SELECT RAISE(ABORT, 'sprint belongs to another project')
    WHERE (SELECT project_id FROM citadel_sprints WHERE id = NEW.sprint_id)
       <> (SELECT project_id FROM citadel_knowledge_entries WHERE id = NEW.entry_id);
END;

CREATE TRIGGER citadel_agents_hired_through_approval BEFORE UPDATE OF status ON citadel_agents
WHEN OLD.status = 'pending_approval' AND NEW.status = 'active' AND NOT EXISTS (
    SELECT 1 FROM citadel_approvals WHERE kind = 'hire_agent' AND agent_id = NEW.id
    AND status = 'approved')
BEGIN
    SELECT RAISE(ABORT, 'an agent is hired only through an approved hire_agent approval');
END;

CREATE TRIGGER citadel_issues_points_frozen_update BEFORE UPDATE OF points ON citadel_issues
WHEN NEW.points IS NOT OLD.points AND EXISTS (SELECT 1 FROM citadel_approvals
    WHERE sprint_id = NEW.sprint_id AND kind = 'sprint_commit' AND status = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'estimates are frozen while the sprint commit awaits approval');
END;

CREATE TRIGGER citadel_issues_points_frozen_insert BEFORE INSERT ON citadel_issues
WHEN NEW.points IS NOT NULL AND EXISTS (SELECT 1 FROM citadel_approvals
    WHERE sprint_id = NEW.sprint_id AND kind = 'sprint_commit' AND status = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'estimates are frozen while the sprint commit awaits approval');
END;

CREATE TRIGGER citadel_approvals_same_company BEFORE INSERT ON citadel_approvals
BEGIN
    SELECT RAISE(ABORT, 'requester belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.requested_by_agent_id)
       <> NEW.company_id;
    SELECT RAISE(ABORT, 'agent belongs to another company')
    WHERE (SELECT company_id FROM citadel_agents WHERE id = NEW.agent_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'issue belongs to another company')
    WHERE (SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id
           WHERE i.id = NEW.issue_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'sprint belongs to another company')
    WHERE (SELECT p.company_id FROM citadel_sprints s JOIN citadel_projects p ON p.id = s.project_id
           WHERE s.id = NEW.sprint_id) <> NEW.company_id;
    SELECT RAISE(ABORT, 'requirement belongs to another company')
    WHERE (SELECT company_id FROM citadel_requirements WHERE id = NEW.requirement_id) <> NEW.company_id;
END;

CREATE TRIGGER citadel_teams_leave_projects AFTER DELETE ON citadel_teams
BEGIN
    -- Drops the team's id from each project's JSON array of ids (no json_each: the module
    -- migration guard refuses table-valued functions). The ids are a set of integers.
    UPDATE citadel_projects SET extra_team_ids = '[' || trim(replace(',' ||
        replace(replace(replace(extra_team_ids, '[', ''), ']', ''), ' ', '') || ',',
        ',' || OLD.id || ',', ','), ',') || ']'
    WHERE extra_team_ids <> '[]';
END;

CREATE TRIGGER citadel_cost_events_budget_spend AFTER INSERT ON citadel_cost_events
BEGIN
    INSERT INTO citadel_budget_spend (budget_id, period_key, tokens, usd_micros)
    SELECT b.id, CASE b.period WHEN 'day' THEN date(NEW.created_at)
               WHEN 'week' THEN date(NEW.created_at, '-6 days', 'weekday 1')
               WHEN 'month' THEN strftime('%Y-%m', NEW.created_at) ELSE 'total' END,
           NEW.input_tokens + NEW.output_tokens + NEW.cache_tokens,
           coalesce(NEW.cost_usd_micros, 0)
    FROM citadel_budgets b
    WHERE b.agent_id = NEW.agent_id
       OR b.company_id = (SELECT company_id FROM citadel_agents WHERE id = NEW.agent_id)
       OR b.department_id IN (SELECT t.department_id FROM citadel_team_memberships m
           JOIN citadel_teams t ON t.id = m.team_id WHERE m.agent_id = NEW.agent_id)
       OR b.project_id = (SELECT project_id FROM citadel_issues WHERE id = NEW.issue_id)
       OR b.sprint_id = (SELECT sprint_id FROM citadel_issues WHERE id = NEW.issue_id)
       OR b.issue_id = NEW.issue_id
    ON CONFLICT (budget_id, period_key) DO UPDATE SET tokens = tokens + excluded.tokens,
        usd_micros = usd_micros + excluded.usd_micros;
END;

CREATE TRIGGER citadel_cost_events_insert_only
BEFORE UPDATE OF id, user_id, run_id, agent_id, input_tokens, output_tokens, cache_tokens,
    cost_usd_micros, priced, idempotency_key, created_at ON citadel_cost_events
WHEN OLD.priced = 1 OR NEW.priced = 0 OR NEW.id IS NOT OLD.id OR NEW.user_id IS NOT OLD.user_id
    OR NEW.run_id IS NOT OLD.run_id OR NEW.agent_id IS NOT OLD.agent_id
    OR NEW.input_tokens IS NOT OLD.input_tokens OR NEW.output_tokens IS NOT OLD.output_tokens
    OR NEW.cache_tokens IS NOT OLD.cache_tokens
    OR NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'cost events are insert-only');
END;

-- The agent avatar palettes (a new agent is given the least-used one of its company).
INSERT INTO citadel_avatar_palettes (position, id, name) VALUES
    (1, 'neon-tide', 'Neon Tide'), (2, 'aurora', 'Aurora'), (3, 'ultraviolet', 'Ultraviolet'),
    (4, 'glacier', 'Glacier'), (5, 'ember', 'Ember'), (6, 'orchid', 'Orchid'),
    (7, 'lagoon', 'Lagoon'), (8, 'citrine', 'Citrine'), (9, 'coral', 'Coral'), (10, 'jade', 'Jade'),
    (11, 'abyss', 'Abyss'), (12, 'dusk', 'Dusk'), (13, 'copper', 'Copper'),
    (14, 'lime-circuit', 'Lime Circuit'), (15, 'sakura', 'Sakura'), (16, 'cobalt', 'Cobalt'),
    (17, 'steel', 'Steel');
