//! Shared fixtures of the slice S3 store tests.

use ainkrad_core::audit::AuditActor;
use sqlx::{Error, SqlitePool};

use crate::domain::org::{AgentStatus, CompanyId, Harness, NewAgent, OrgRole};

pub use crate::testing::db;
pub use ainkrad_core_server::api::v1::BY;

pub const NOW: &str = "2026-10-21T10:00:00.000Z";

pub fn new_agent(company_id: CompanyId, name: &str, org_role: OrgRole) -> NewAgent {
    NewAgent {
        company_id,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec!["macos".to_owned()],
        status: AgentStatus::Active,
    }
}

pub fn is_constraint(e: &Error) -> bool {
    matches!(e, Error::Database(d) if d.message().contains("constraint failed"))
}

pub fn is_raised(e: &Error, message: &str) -> bool {
    matches!(e, Error::Database(d) if d.message() == message)
}

/// The module's audit actions, oldest first.
pub async fn actions(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_events WHERE action LIKE 'citadel.%' ORDER BY seq")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[allow(dead_code)]
pub const SYSTEM: AuditActor = AuditActor::System;
