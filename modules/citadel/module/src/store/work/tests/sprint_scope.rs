//! The admin's scope changes to an active sprint, unique sprint names, and deleting an empty
//! planned sprint.

use super::sprints::{finish, planned, pointed, sprint_actions};
use super::*;

const BY: AuditActor = core_user(ADMIN);

#[tokio::test]
async fn admin_changes_active_scope() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let s = plan_sprint(pool, &planned(p.id, "S1"), BY).await.unwrap();
    let a = pointed(pool, p.id, "a", 3).await;
    add_to_sprint(pool, s.id, a.id, BY).await.unwrap();
    start_sprint(pool, s.id, BY).await.unwrap();

    let b = pointed(pool, p.id, "b", 5).await;
    let added = add_to_sprint(pool, s.id, b.id, BY).await.unwrap();
    assert_eq!(added.sprint_id, Some(s.id));
    let now = "2020-03-09T00:00:00Z";
    let report = sprint_report(pool, s.id, now).await.unwrap().unwrap();
    assert_eq!(report.committed, Some(8));
    // An unpointed issue does not join an active sprint.
    let u = create_issue(pool, &new_issue(p.id, "u")).await.unwrap();
    let e = add_to_sprint(pool, s.id, u.id, BY).await.unwrap_err();
    assert!(
        matches!(&e, SprintError::Unpointed(ids) if *ids == vec![u.id]),
        "{e}"
    );

    let back = remove_from_sprint(pool, a.id, BY).await.unwrap();
    assert_eq!(back.sprint_id, None);
    let report = sprint_report(pool, s.id, now).await.unwrap().unwrap();
    assert_eq!(report.committed, Some(5));
    assert_eq!(
        sprint_actions(pool, s.id).await,
        [
            "sprint.planned",
            "sprint.started",
            "sprint.scope_added",
            "sprint.scope_removed"
        ]
    );
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'citadel.sprint.scope_added' AND entity_id = ?",
    )
    .bind(s.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    let details: serde_json::Value = serde_json::from_str(&details).unwrap();
    assert_eq!(
        details,
        serde_json::json!({"issue": b.id.0, "points": 5, "committed": 8, "company_id": 1})
    );

    // Closed: fixed for everyone (b is done, so it stays in it).
    finish(pool, b.id).await;
    close_sprint(pool, s.id, None, BY).await.unwrap();
    let e = add_to_sprint(pool, s.id, a.id, BY).await.unwrap_err();
    assert!(matches!(e, SprintError::State(SprintState::Closed)), "{e}");
    let e = remove_from_sprint(pool, b.id, BY).await.unwrap_err();
    assert!(matches!(e, SprintError::State(SprintState::Closed)), "{e}");
}

#[tokio::test]
async fn a_taken_name_gets_the_next_number() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let names = [
        "WRK Sprint 1",
        "WRK Sprint 1",
        "WRK Sprint 1",
        "Alpha",
        "Alpha",
    ];
    let mut got = vec![];
    for n in names {
        got.push(plan_sprint(pool, &planned(p.id, n), BY).await.unwrap().name);
    }
    assert_eq!(
        got,
        [
            "WRK Sprint 1",
            "WRK Sprint 2",
            "WRK Sprint 3",
            "Alpha",
            "Alpha 2"
        ]
    );
}

#[tokio::test]
async fn only_an_empty_planned_sprint_is_deleted() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let s = plan_sprint(pool, &planned(p.id, "S1"), BY).await.unwrap();
    let a = pointed(pool, p.id, "a", 3).await;
    add_to_sprint(pool, s.id, a.id, BY).await.unwrap();
    let e = delete_empty_sprint(pool, s.id, BY).await.unwrap_err();
    assert!(matches!(e, SprintError::NotEmpty(1)), "{e}");
    assert!(e.to_string().contains("`sprint remove` them first"), "{e}");

    // Active, then closed: kept.
    start_sprint(pool, s.id, BY).await.unwrap();
    remove_from_sprint(pool, a.id, BY).await.unwrap();
    let e = delete_empty_sprint(pool, s.id, BY).await.unwrap_err();
    assert!(matches!(e, SprintError::State(SprintState::Active)), "{e}");
    close_sprint(pool, s.id, None, BY).await.unwrap();
    let e = delete_empty_sprint(pool, s.id, BY).await.unwrap_err();
    assert!(matches!(e, SprintError::State(SprintState::Closed)), "{e}");

    // Empty and planned: gone, audited.
    let empty = plan_sprint(pool, &planned(p.id, "S2"), BY).await.unwrap();
    let gone = delete_empty_sprint(pool, empty.id, BY).await.unwrap();
    assert_eq!(gone.id, empty.id);
    assert!(get_sprint(pool, empty.id).await.unwrap().is_none());
    assert_eq!(
        sprint_actions(pool, empty.id).await,
        ["sprint.planned", "sprint.deleted"]
    );
    let (kind, actor, details): (String, i64, String) = sqlx::query_as(
        "SELECT actor_kind, actor_id, details FROM audit_events WHERE action = 'citadel.sprint.deleted' AND entity_id = ?",
    )
    .bind(empty.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!((kind.as_str(), actor), ("user", ADMIN.0));
    let details: serde_json::Value = serde_json::from_str(&details).unwrap();
    assert_eq!(
        details,
        serde_json::json!({"name": "S2", "project": p.id.0, "approvals": [], "budgets": [],
                           "company_id": 1})
    );
    let e = delete_empty_sprint(pool, empty.id, BY).await.unwrap_err();
    assert!(matches!(e, SprintError::NotFound), "{e}");
}
