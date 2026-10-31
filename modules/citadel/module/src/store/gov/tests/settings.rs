//! Governance limits are settings (E15.17): approval deadlines per kind, the knowledge and
//! skill budgets, and a new budget's warning. The monolith changed each per company or project;
//! the Core's settings are server-wide, so those scopes are not ported (`#[ignore]`d below), and
//! the server-wide behaviour is checked by `approvals::deadlines_are_per_kind...` and here.

use super::*;

const NOW: &str = "2026-10-22T10:00:00.000Z";

#[tokio::test]
#[ignore = "per-company settings scope"]
async fn every_approval_kind_takes_its_deadline_from_settings() {
    todo!("monolith store/gov/tests/settings.rs: per-company and per-project deadlines")
}

#[tokio::test]
#[ignore = "per-company settings scope"]
async fn the_knowledge_budget_is_the_projects_setting() {
    todo!("monolith store/gov/tests/settings.rs: a project-scoped knowledge.budget_bytes")
}

#[tokio::test]
#[ignore = "per-company settings scope; skills_for_run is not ported yet"]
async fn the_skill_budget_is_the_runs_projects_setting() {
    todo!("monolith store/gov/tests/settings.rs: company and project skills.budget_bytes")
}

#[tokio::test]
#[ignore = "per-company settings scope"]
async fn a_new_budget_warns_at_its_companys_setting() {
    todo!("monolith store/gov/tests/settings.rs: budget.warn_percent per company")
}

#[tokio::test]
async fn the_server_wide_values_are_read() {
    let db = db().await;
    let pool = &db.pool;
    let (_, _, p) = fixture(pool, "A").await;
    let kind = KnowledgeKind::Landmine;
    add_knowledge(pool, p.id, kind, "Flaky port", "Use 7701.", ADMIN)
        .await
        .unwrap();
    assert_eq!(
        project_knowledge(pool, p.id).await.unwrap().entries.len(),
        1
    );
    crate::settings::handle()
        .set(pool, "knowledge.budget_bytes", "0", BY, NOW)
        .await
        .unwrap();
    let k = project_knowledge(pool, p.id).await.unwrap();
    assert_eq!((k.entries.len(), k.dropped.len()), (0, 1));
    let scope = BudgetScope::Project(p.id);
    assert_eq!(default_warn_percent(pool, &scope).await.unwrap(), 80);
    crate::settings::handle()
        .set(pool, "budget.warn_percent", "75", BY, NOW)
        .await
        .unwrap();
    assert_eq!(default_warn_percent(pool, &scope).await.unwrap(), 75);
}
