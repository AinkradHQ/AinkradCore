//! Citadel's tunables, declared to the Core (`Module::settings`) and read through
//! [`ModuleSettings`] (`ainkrad_core_server::store::modsettings`): stored in the Core's settings
//! table as `module.citadel.<name>`, audited like any setting.
//!
//! The monolith's registry mixed platform and Citadel keys and let a value be set per company or
//! project. The Core's settings are server-wide, so these are too: one value for the module. A
//! per-company or per-project override (the monolith's `SC`/`SCP` scopes) is a later change to the
//! Core store, not a Citadel one; every name, default and bound below is the monolith's.
//! The run engine's and the accounts' keys come with their slices; a slice that reads a new
//! tunable appends its line (append-only).

use ainkrad_core_server::module::{Module, ModuleSetting};
use ainkrad_core_server::store::modsettings::ModuleSettings;
use sqlx::SqlitePool;

use crate::Citadel;
use crate::domain::gov::{KNOWLEDGE_BUDGET_BYTES, SKILL_BUDGET_BYTES};

const DAY: i64 = 86_400;
const YEAR: i64 = 365 * DAY;

const fn s(
    name: &'static str,
    default: i64,
    min: i64,
    max: i64,
    description: &'static str,
) -> ModuleSetting {
    ModuleSetting {
        name,
        default,
        min,
        max,
        description,
    }
}

pub const SETTINGS: &[ModuleSetting] = &[
    s(
        "knowledge.budget_bytes",
        KNOWLEDGE_BUDGET_BYTES as i64,
        0,
        256 * 1024,
        "The most of its project's knowledge a run is given.",
    ),
    s(
        "skills.budget_bytes",
        SKILL_BUDGET_BYTES as i64,
        0,
        512 * 1024,
        "The most of its skills' bodies a run is given.",
    ),
    s(
        "skills.max_bytes",
        64 * 1024,
        1,
        512 * 1024,
        "The largest skill body the admin may publish.",
    ),
    s(
        "sprint.velocity_window",
        3,
        1,
        20,
        "Closed sprints a sprint review compares its velocity against.",
    ),
    s(
        "approval.deadline.sprint_commit",
        0,
        0,
        YEAR,
        "How long a sprint commit approval waits before it expires; 0 waits until decided.",
    ),
    s(
        "approval.deadline.pr_merge",
        0,
        0,
        YEAR,
        "How long a PR merge approval waits before it expires; 0 waits until decided.",
    ),
    s(
        "approval.deadline.budget_overrun",
        0,
        0,
        YEAR,
        "How long a budget overrun approval waits before it expires; 0 waits until decided.",
    ),
    s(
        "approval.deadline.hire_agent",
        0,
        0,
        YEAR,
        "How long a hire approval waits before it expires; 0 waits until decided.",
    ),
    s(
        "approval.deadline.permission_escalation",
        900,
        1,
        7 * DAY,
        "How long an escalated tool call waits for a reviewer before the runner denies it.",
    ),
    s(
        "approval.deadline.plan_approval",
        0,
        0,
        YEAR,
        "How long a requirement's plan approval waits before it expires; 0 waits until decided.",
    ),
    s(
        "approval.deadline.workflow_push",
        0,
        0,
        YEAR,
        "How long a workflow push approval waits for a human to push; 0 waits until decided.",
    ),
    s(
        "approval.issue_allow_secs",
        DAY,
        60,
        30 * DAY,
        "How long \"allow for this issue\" on a permission escalation lets the same call through.",
    ),
    s(
        "budget.warn_percent",
        80,
        1,
        100,
        "A new budget's warning threshold when none is given.",
    ),
    s(
        "artifact.max_file_bytes",
        10_000_000,
        1_000,
        12_000_000,
        "The largest file an agent may publish as an artifact.",
    ),
    s(
        "artifact.company_quota_bytes",
        2_000_000_000,
        1_000_000,
        1_000_000_000_000,
        "The most artifact bytes one company may hold.",
    ),
    s(
        "profile.budget_bytes",
        4096,
        0,
        64 * 1024,
        "The most of its project's profile a run is given in its instructions.",
    ),
    s(
        "avatar.max_bytes",
        512 * 1024,
        1024,
        8 * 1024 * 1024,
        "The largest image the admin may upload as an agent's avatar or a company's logo.",
    ),
    s(
        "flow.window_secs",
        30 * DAY,
        DAY,
        YEAR,
        "The window a project's throughput and cycle and lead times are measured over.",
    ),
    s(
        "account.warn_percent",
        80,
        1,
        100,
        "An account limit's warning threshold when none is given.",
    ),
    s(
        "account.drop_threshold",
        3,
        1,
        50,
        "Provider drops in account.drop_window_secs that mark an account unhealthy.",
    ),
    s(
        "account.drop_window_secs",
        1800,
        60,
        DAY,
        "The window over which an account's provider drops are counted.",
    ),
    s(
        "account.unhealthy_secs",
        1800,
        60,
        7 * DAY,
        "How long an account stays cooling after repeated provider drops.",
    ),
    s(
        "run.token_cap",
        2_000_000,
        1_000,
        100_000_000,
        "The most tokens one run may use before the engine stops it (budgets can stop it sooner).",
    ),
    s(
        "run.cache_weight_divisor",
        10,
        1,
        100,
        "How much a run's cache reads and writes count against run.token_cap, as a divisor: 10 \
         counts a tenth, so the cap tracks the work a run does rather than the context it re-reads; \
         1 counts every token in full. Budgets and the issue cap always count in full.",
    ),
    s(
        "issue.token_cap",
        0,
        0,
        1_000_000_000,
        "The most tokens all the runs of one issue may use together; 0 sets no cap.",
    ),
    s(
        "wake.max_attempts",
        3,
        1,
        20,
        "Attempts a wake gets before a failed run stops being retried.",
    ),
    s(
        "wake.retry_backoff_max_secs",
        600,
        30,
        DAY,
        "The longest wait before a failed run is retried.",
    ),
    s(
        "run.token_ttl_secs",
        4 * 3600,
        60,
        DAY,
        "How long a run's token for its agent's callbacks lives (it is revoked when the run ends).",
    ),
    s(
        "mcp.enabled",
        0,
        0,
        1,
        "Whether a run's agent is handed a token for the MCP server (1) or none (0). The engine \
         works without it; with it an agent reads and updates its own issue.",
    ),
    s(
        "mcp.max_calls_per_run",
        2000,
        1,
        100_000,
        "The most tool calls one run's token may make; past it every call is refused.",
    ),
    s(
        "mcp.max_issues_per_run",
        50,
        0,
        10000,
        "The most issues, subtasks, epics and planned tasks one run may create.",
    ),
    s(
        "mcp.max_approvals_per_run",
        5,
        0,
        1000,
        "The most approvals one run may ask for.",
    ),
    s(
        "mcp.max_comments_per_run",
        200,
        0,
        100000,
        "The most comments one run may write.",
    ),
    s(
        "mcp.max_knowledge_per_run",
        10,
        0,
        1000,
        "The most knowledge proposals one run may make.",
    ),
    s(
        "mcp.max_repo_requests_per_run",
        10,
        0,
        1000,
        "The most repo requests one run may make.",
    ),
    s(
        "mcp.max_questions_per_run",
        5,
        0,
        100,
        "The most questions one run may put to a human with ask_human.",
    ),
    s(
        "mcp.max_artifacts_per_run",
        20,
        0,
        1_000,
        "The most artifacts one run may publish.",
    ),
    s(
        "wake.timer_batch",
        50,
        1,
        1_000,
        "The most timer wakes one pass of the timer job queues.",
    ),
];

/// Citadel's settings handle.
pub fn handle() -> ModuleSettings {
    ModuleSettings::of(&Citadel::default() as &dyn Module)
}

/// `name`'s value: the stored one, else the default. `name` must be one of [`SETTINGS`]; an
/// unknown name is a programming error: an error here (a 500 through `error::refused`), never a silent default.
pub async fn value(pool: &SqlitePool, name: &str) -> Result<i64, sqlx::Error> {
    handle()
        .get(pool, name)
        .await
        .map_err(|e| sqlx::Error::Configuration(e.to_string().into()))
}

/// [`value`] inside the caller's transaction.
pub async fn value_in(conn: &mut sqlx::SqliteConnection, name: &str) -> Result<i64, sqlx::Error> {
    handle()
        .get_in(conn, name)
        .await
        .map_err(|e| sqlx::Error::Configuration(e.to_string().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declared_settings_are_legal_and_unique() {
        let modules: [std::sync::Arc<dyn Module>; 1] = [std::sync::Arc::new(Citadel::default())];
        let _ = ainkrad_core_server::module::mount(&modules);
    }

    #[tokio::test]
    async fn a_default_is_read_and_an_undeclared_name_is_an_error() {
        let db = crate::testing::db().await;
        assert_eq!(value(&db.pool, "sprint.velocity_window").await.unwrap(), 3);
        assert_eq!(value(&db.pool, "run.token_cap").await.unwrap(), 2_000_000);
        assert!(value(&db.pool, "run.nonsense").await.is_err());
    }
}
