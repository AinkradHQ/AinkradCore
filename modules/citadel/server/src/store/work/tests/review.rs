//! Sprint review and retro (E5.5): the review stored at close, with exact numbers on a fixed
//! fixture, and retro proposals linked to the sprint, never accepted here.

use citadel_core::audit::NewAuditEvent;
use citadel_core::gov::{KnowledgeKind, KnowledgeStatus};
use citadel_core::work::IssueTransition;
use serde_json::json;

use super::*;
use crate::store::audit;

const BY: AuditActor = AuditActor::User(ADMIN);

async fn pointed(pool: &SqlitePool, p: ProjectId, title: &str, points: u32) -> IssueId {
    let i = NewIssue {
        points: Some(points),
        ..new_issue(p, title)
    };
    create_issue(pool, &i).await.unwrap().id
}

async fn step(pool: &SqlitePool, i: IssueId, t: IssueTransition) {
    transition_issue(pool, i, &t, BY).await.unwrap();
}

/// Appends `action` about issue `i` (an `issue.*` event) or naming it in its details.
async fn event(pool: &SqlitePool, action: &str, i: IssueId) {
    let e = NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: Some(citadel_core::audit::AuditEntity {
            kind: if action.starts_with("issue.") {
                "issue"
            } else {
                "run"
            }
            .to_owned(),
            id: i.0,
        }),
        company_id: None,
        run_id: None,
        details: json!({"issue": i.0}).to_string(),
    };
    audit::append(pool, &e).await.unwrap();
}

/// A sprint already closed with these points.
async fn closed(pool: &SqlitePool, p: ProjectId, name: &str, completed: u32) {
    let s = raw_sprint(pool, p, name, SprintState::Closed).await;
    sqlx::query("UPDATE sprints SET committed_points = 10, completed_points = ? WHERE id = ?")
        .bind(completed)
        .bind(s.id.0)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn closing_stores_the_review_with_exact_numbers() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    closed(pool, p.id, "S-2", 4).await;
    closed(pool, p.id, "S-1", 8).await;
    let s1 = plan_sprint(pool, &dated(p.id, "S1"), BY).await.unwrap();
    let s2 = plan_sprint(pool, &dated(p.id, "S2"), BY).await.unwrap();
    let (a, b) = (
        pointed(pool, p.id, "a", 3).await,
        pointed(pool, p.id, "b", 5).await,
    );
    let (c, d) = (
        pointed(pool, p.id, "c", 2).await,
        pointed(pool, p.id, "d", 1).await,
    );
    for i in [a, b, c, d] {
        add_to_sprint(pool, s1.id, i, BY).await.unwrap();
    }
    let outside = create_issue(pool, &new_issue(p.id, "outside"))
        .await
        .unwrap()
        .id;
    // Before the start: not this sprint's story.
    event(pool, "issue.blocked", c).await;
    start_sprint(pool, s1.id, BY).await.unwrap();
    assert_eq!(sprint_review(pool, s1.id).await.unwrap(), None);

    for i in [a, c] {
        step(pool, i, IssueTransition::Start).await;
        step(pool, i, IssueTransition::Done).await;
    }
    let link = BlockerLink {
        blocker: outside,
        blocked: b,
    };
    add_blocker(pool, link).await.unwrap();
    step(pool, b, IssueTransition::Start).await;
    step(pool, b, IssueTransition::Block).await;
    event(pool, "loop_breaker.tripped", b).await;
    event(pool, "loop_breaker.tripped", b).await;
    close_sprint(pool, s1.id, Some(s2.id), BY).await.unwrap();

    let review = sprint_review(pool, s1.id).await.unwrap().unwrap();
    assert_eq!(
        review,
        json!({
            "committed": 11,
            "completed": 5,
            "carried": [
                {"issue": b.0, "key": "CIT-2", "title": "b", "points": 5, "state": "blocked"},
                {"issue": d.0, "key": "CIT-4", "title": "d", "points": 1, "state": "backlog"},
            ],
            "carried_to": s2.id.0,
            "velocity": {"previous_mean": 6.0, "delta": -1.0, "sprints": 2},
            "blocked": [{"issue": b.0, "key": "CIT-2", "times": 1}],
            "escalated": [{"issue": b.0, "key": "CIT-2", "times": 2}],
        })
    );
    let report = sprint_report(pool, s1.id, "2026-11-04T00:00:00Z").await;
    assert_eq!(report.unwrap().unwrap().completed, 5);
}

#[tokio::test]
async fn the_velocity_window_is_the_projects_setting() {
    use citadel_core::settings::{Key, Scope};
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    closed(pool, p.id, "S-3", 2).await;
    closed(pool, p.id, "S-2", 4).await;
    closed(pool, p.id, "S-1", 8).await;
    let at = Scope::Project(p.id);
    crate::store::settings::set(
        pool,
        Key::VelocityWindow,
        at,
        "1",
        BY,
        "2026-10-22T10:00:00Z",
    )
    .await
    .unwrap();
    let s1 = plan_sprint(pool, &dated(p.id, "S1"), BY).await.unwrap();
    start_sprint(pool, s1.id, BY).await.unwrap();
    close_sprint(pool, s1.id, None, BY).await.unwrap();
    let review = sprint_review(pool, s1.id).await.unwrap().unwrap();
    assert_eq!(
        review["velocity"],
        json!({"previous_mean": 8.0, "delta": -8.0, "sprints": 1}),
        "only the last sprint, not the default three"
    );
}

#[tokio::test]
async fn retro_items_are_proposals_linked_to_the_closed_sprint() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let po = agent(pool, c, "PO").await;
    let s = plan_sprint(pool, &dated(p.id, "S1"), BY).await.unwrap();
    let item = |kind, title: &str| RetroItem {
        kind,
        title: title.to_owned(),
        body: format!("{title}, in detail"),
    };
    let items = [
        item(KnowledgeKind::Decision, "Pair on migrations"),
        item(KnowledgeKind::Landmine, "The runner's clock drifts"),
    ];
    let early = propose_retro(pool, s.id, &items, po).await.unwrap_err();
    assert!(
        matches!(early, SprintError::State(SprintState::Planned)),
        "{early}"
    );
    start_sprint(pool, s.id, BY).await.unwrap();
    close_sprint(pool, s.id, None, BY).await.unwrap();

    let state = [item(KnowledgeKind::State, "Where we are")];
    let refused = propose_retro(pool, s.id, &state, po).await.unwrap_err();
    assert!(
        matches!(refused, SprintError::Db(Error::InvalidArgument(_))),
        "{refused}"
    );
    let proposed = propose_retro(pool, s.id, &items, po).await.unwrap();
    assert_eq!(proposed.len(), 2);
    assert!(
        proposed
            .iter()
            .all(|k| k.status == KnowledgeStatus::Proposed
                && k.proposed_by == Some(po)
                && k.decided_by.is_none()
                && k.project_id == p.id)
    );
    assert_eq!(retro_items(pool, s.id).await.unwrap(), proposed);
    let accepted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM knowledge_entries WHERE status <> 'proposed'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(accepted, 0, "nothing is accepted here");
}

fn dated(p: ProjectId, name: &str) -> NewSprint {
    NewSprint {
        starts_on: Some("2026-10-21".to_owned()),
        ends_on: Some("2026-11-03".to_owned()),
        ..new_sprint(p, name, SprintState::Planned)
    }
}
