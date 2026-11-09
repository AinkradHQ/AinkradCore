//! Governance limits are settings (E15.17): approval deadlines per kind, the knowledge and
//! skill budgets, and a new budget's warning. Each is changed and the behaviour follows.

use citadel_core::audit::AuditActor;
use citadel_core::gov::KnowledgeKind;
use citadel_core::settings::{Key, Scope};

use super::approvals::{issue, open};
use super::skills::run;
use super::*;
use crate::store::settings;

const NOW: &str = "2026-10-22T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(ADMIN);

async fn set(pool: &SqlitePool, key: Key, at: Scope, value: i64) {
    settings::set(pool, key, at, &value.to_string(), BY, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn every_approval_kind_takes_its_deadline_from_settings() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let i = issue(pool, &p).await;
    let kinds = [
        (ApprovalKind::SprintCommit, "2026-10-22T10:01:00.000Z"),
        (ApprovalKind::PrMerge, "2026-10-22T10:02:00.000Z"),
        (ApprovalKind::BudgetOverrun, "2026-10-22T10:03:00.000Z"),
        (ApprovalKind::HireAgent, "2026-10-22T10:04:00.000Z"),
        (
            ApprovalKind::PermissionEscalation,
            "2026-10-22T10:05:00.000Z",
        ),
    ];
    for (n, (kind, expires)) in kinds.into_iter().enumerate() {
        let key = Key::approval_deadline(kind);
        let default = open(pool, c, po, i, kind).await.expires_at;
        let fifteen = (kind == ApprovalKind::PermissionEscalation)
            .then(|| "2026-10-22T10:15:00.000Z".to_owned());
        assert_eq!(default, fifteen, "{kind:?}: the default");
        set(pool, key, Scope::Company(c), 60 * (n as i64 + 1)).await;
        let opened = open(pool, c, po, i, kind).await;
        assert_eq!(opened.expires_at.as_deref(), Some(expires), "{kind:?}");
    }
    // The project's value beats the company's for an approval about one of its issues.
    let escalation = Key::DeadlinePermissionEscalation;
    set(pool, escalation, Scope::Project(p.id), 30).await;
    let opened = open(pool, c, po, i, ApprovalKind::PermissionEscalation).await;
    assert_eq!(
        opened.expires_at.as_deref(),
        Some("2026-10-22T10:00:30.000Z")
    );
}

#[tokio::test]
async fn the_knowledge_budget_is_the_projects_setting() {
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
    set(pool, Key::KnowledgeBudgetBytes, Scope::Project(p.id), 0).await;
    let k = project_knowledge(pool, p.id).await.unwrap();
    assert_eq!((k.entries.len(), k.dropped.len()), (0, 1));
}

#[tokio::test]
async fn the_skill_budget_is_the_runs_projects_setting() {
    let db = db().await;
    let pool = &db.pool;
    let (c, dev, p) = fixture(pool, "A").await;
    let attach = SkillAttach::Company;
    publish_skill(pool, c, "review", "Read the diff.", &attach, BY)
        .await
        .unwrap();
    let r = run(pool, dev, Some(issue(pool, &p).await)).await;
    assert_eq!(skills_for_run(pool, r).await.unwrap().skills.len(), 1);
    set(pool, Key::SkillBudgetBytes, Scope::Company(c), 4).await;
    let s = skills_for_run(pool, r).await.unwrap();
    assert_eq!(
        (s.skills.len(), s.dropped.len()),
        (0, 1),
        "the company's 4 bytes"
    );
    set(pool, Key::SkillBudgetBytes, Scope::Project(p.id), 1024).await;
    assert_eq!(
        skills_for_run(pool, r).await.unwrap().skills.len(),
        1,
        "the project's"
    );
}

#[tokio::test]
async fn a_new_budget_warns_at_its_companys_setting() {
    let db = db().await;
    let pool = &db.pool;
    let (a, _, p) = fixture(pool, "A").await;
    let (b, _, _) = fixture(pool, "B").await;
    let warn = |scope| async move { default_warn_percent(pool, &scope).await.unwrap() };
    assert_eq!(warn(BudgetScope::Project(p.id)).await, 80);
    set(pool, Key::BudgetWarnPercent, Scope::Server, 75).await;
    set(pool, Key::BudgetWarnPercent, Scope::Company(a), 60).await;
    assert_eq!(warn(BudgetScope::Project(p.id)).await, 60);
    assert_eq!(warn(BudgetScope::Company(a)).await, 60);
    assert_eq!(
        warn(BudgetScope::Company(b)).await,
        75,
        "B inherits the server's"
    );
}
