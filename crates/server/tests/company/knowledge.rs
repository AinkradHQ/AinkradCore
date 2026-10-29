//! E8.2's acceptance: a landmine a developer proposes in sprint 1 and the team lead accepts is
//! in a sprint-2 run's context and instructions, end to end through the runner and MCP.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::work::{NewSprint, ProjectMode, SprintState};
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::work::{self, Commit};
use serde_json::json;

use super::stage::{ADMIN, Stage};

const LANDMINE: &str = "Port 7700 is taken on the CI box";

#[tokio::test]
async fn a_landmine_accepted_in_sprint_1_reaches_a_sprint_2_run() {
    let mut stage = Stage::new("knowledge").await;
    let o = stage.org().await;
    let project = stage.project(&o, "KB", ProjectMode::Scrum).await;
    let pool = stage.pool.clone();
    let admin = AuditActor::User(ADMIN);
    let sprint = |name: &str| NewSprint {
        project_id: project,
        name: name.to_owned(),
        goal: String::new(),
        state: SprintState::Planned,
        starts_on: Some("2026-10-22".to_owned()),
        ends_on: Some("2026-11-04".to_owned()),
    };
    let commit = |s| {
        let pool = pool.clone();
        let (po, now) = (o.po, SystemClock.now());
        async move {
            let started = work::commit_sprint(&pool, s, po, None, None, &now).await;
            assert!(matches!(started, Ok(Commit::Started(_))), "{started:?}");
        }
    };

    // Sprint 1: the developer proposes a landmine while working its issue.
    let s1 = work::plan_sprint(&pool, &sprint("S1"), admin)
        .await
        .unwrap()
        .id;
    let build = stage.issue(project, "Build the server", Some(s1)).await;
    commit(s1).await;
    let landmine = json!({"kind": "landmine", "title": LANDMINE, "body": "Use 7710."});
    stage
        .play(
            build,
            &[
                ("transition", json!({"transition": "start"})),
                ("propose_knowledge", landmine),
                ("transition", json!({"transition": "done"})),
            ],
        )
        .await;
    stage.assign(build, o.dev).await;
    assert_eq!(stage.ended(build, 1).await, "succeeded");
    let proposed = stage.replies(build, 1).await;
    let entry = proposed[1]["knowledge_entry_id"]
        .as_i64()
        .expect("proposed");
    assert_eq!(proposed[1]["status"], "proposed");
    assert!(!stage.instructions(build, 1).await.contains(LANDMINE));

    // The team lead finds it in its context and accepts it.
    let review = stage.issue(project, "Review the proposals", None).await;
    stage
        .play(
            review,
            &[
                ("get_context", json!({})),
                (
                    "review_knowledge",
                    json!({"entry_id": entry, "verdict": "accept", "reason": "Bit us"}),
                ),
            ],
        )
        .await;
    stage.assign(review, o.lead).await;
    assert_eq!(stage.ended(review, 1).await, "succeeded");
    let reviewed = stage.replies(review, 1).await;
    assert_eq!(
        reviewed[0]["proposals"][0]["title"], LANDMINE,
        "{reviewed:?}"
    );
    assert_eq!(reviewed[1]["status"], "accepted", "{reviewed:?}");

    // Sprint 2: a new run is told.
    work::close_sprint(&pool, s1, None, admin).await.unwrap();
    let s2 = work::plan_sprint(&pool, &sprint("S2"), admin)
        .await
        .unwrap()
        .id;
    let next = stage.issue(project, "Ship it", Some(s2)).await;
    commit(s2).await;
    stage.play(next, &[("get_context", json!({}))]).await;
    stage.assign(next, o.dev).await;
    assert_eq!(stage.ended(next, 1).await, "succeeded");
    let ctx = &stage.replies(next, 1).await[0];
    assert_eq!(ctx["knowledge"][0]["title"], LANDMINE, "{ctx}");
    assert_eq!(ctx["knowledge"][0]["kind"], "landmine");
    let told = stage.instructions(next, 1).await;
    assert!(
        told.contains(&format!("## landmine {entry}: {LANDMINE}\n\nUse 7710.")),
        "{told}"
    );
}
