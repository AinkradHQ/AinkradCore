//! E9.4's acceptance against a fake Linear: issues and edits round-trip both ways, a field both
//! sides changed goes to the later writer (audited), a state the engine refuses is put back in
//! Linear, and nothing either side wrote echoes back.

use std::time::Duration;

use citadel_core::audit::AuditActor;
use citadel_core::work::{IssueId, IssueState, IssueTransition, NextActor, ProjectMode};
use citadel_server::store::linear::{ProjectLinear, set_project_linear};
use citadel_server::store::work::{get_issue, list_issues, transition_issue, update_issue};
use ainkrad_providers::fake;

use super::stage::{ADMIN, Stage};

async fn sync(stage: &Stage) {
    citadel_server::linear::sync(&stage.pool, &ainkrad_providers::client())
        .await
        .unwrap();
}

async fn retitle(stage: &Stage, issue: IssueId, title: &str) {
    let mut i = get_issue(&stage.pool, issue).await.unwrap().unwrap();
    i.title = title.to_owned();
    assert!(update_issue(&stage.pool, &i).await.unwrap());
}

async fn actions(stage: &Stage) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_events WHERE action LIKE 'linear.%' ORDER BY seq")
        .fetch_all(&stage.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn edits_round_trip_both_ways_and_nothing_echoes() {
    let stage = Stage::new("linear").await;
    let o = stage.org().await;
    let project = stage.project(&o, "LN", ProjectMode::Kanban).await;
    let (api, board) = fake::linear("lin_key", "team-1", &["Developer 1"]).await;
    let token_file = stage.dir.join("linear-token");
    std::fs::write(&token_file, "lin_key\n").unwrap();
    let config = ProjectLinear {
        project_id: project,
        team_id: "team-1".to_owned(),
        api_url: api,
        token_file,
        cursor: None,
    };
    assert!(
        set_project_linear(&stage.pool, &config, AuditActor::User(ADMIN))
            .await
            .unwrap()
    );

    // First pass: Linear's issue comes in, Citadel's goes out.
    let ours = stage.issue(project, "Citadel side", None).await;
    let filed = board.lock().unwrap().file("Filed in Linear", "Backlog");
    sync(&stage).await;
    let issues = list_issues(&stage.pool, project).await.unwrap();
    let theirs = issues
        .iter()
        .find(|i| i.title == "Filed in Linear")
        .unwrap();
    assert_eq!(theirs.state, IssueState::Backlog);
    let theirs = theirs.id;
    let exported = board.lock().unwrap().by_identifier("ENG-2");
    assert_eq!(exported.title, "Citadel side");
    assert_eq!(exported.state_id, board.lock().unwrap().state_id("Todo"));
    assert_eq!(board.lock().unwrap().mutations, ["IssueCreate"]);
    // What a sync wrote either way: Linear mutations, and the sync's own audits (every pull
    // or push is one). Not every audit: the stage's runner works the issues meanwhile, and
    // its run's records (`wake.dispatched`, `run.claimed`, …) land whenever they land.
    let settled = |stage: &Stage| {
        let b = board.lock().unwrap().mutations.len();
        let pool = stage.pool.clone();
        async move {
            let a: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM audit_events WHERE action LIKE 'linear.%'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            (b, a)
        }
    };
    let before = settled(&stage).await;
    sync(&stage).await;
    sync(&stage).await;
    assert_eq!(
        settled(&stage).await,
        before,
        "no echo: nothing written either way"
    );

    // Linear → Citadel: a rename and a start, through the engine.
    board.lock().unwrap().edit(&filed, |i| {
        i.title = "Renamed in Linear".to_owned();
        i.state_id = "st-2".to_owned();
    });
    sync(&stage).await;
    let i = get_issue(&stage.pool, theirs).await.unwrap().unwrap();
    assert_eq!(
        (i.title.as_str(), i.state),
        ("Renamed in Linear", IssueState::InProgress)
    );
    assert_eq!(
        board.lock().unwrap().mutations.len(),
        1,
        "nothing pushed back"
    );

    // Citadel → Linear: a rename, a start and an assignee Linear knows by name.
    retitle(&stage, ours, "Renamed in Citadel").await;
    let by = AuditActor::User(ADMIN);
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(o.dev),
    };
    transition_issue(&stage.pool, ours, &to_dev, by)
        .await
        .unwrap();
    sync(&stage).await;
    let pushed = board.lock().unwrap().by_identifier("ENG-2");
    assert_eq!(pushed.title, "Renamed in Citadel");
    assert_eq!(pushed.assignee_id.as_deref(), Some("u-0"), "Developer 1");
    let before = settled(&stage).await;
    sync(&stage).await;
    assert_eq!(settled(&stage).await, before, "no echo of its own push");

    // Both rename it: the later writer wins, either way round, and it is audited.
    retitle(&stage, theirs, "Citadel first").await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    board
        .lock()
        .unwrap()
        .edit(&filed, |i| i.title = "Linear later".to_owned());
    sync(&stage).await;
    let i = get_issue(&stage.pool, theirs).await.unwrap().unwrap();
    assert_eq!(i.title, "Linear later");
    board
        .lock()
        .unwrap()
        .edit(&filed, |i| i.title = "Linear first".to_owned());
    tokio::time::sleep(Duration::from_millis(5)).await;
    retitle(&stage, theirs, "Citadel later").await;
    sync(&stage).await;
    let i = get_issue(&stage.pool, theirs).await.unwrap().unwrap();
    assert_eq!(i.title, "Citadel later");
    assert_eq!(
        board.lock().unwrap().by_identifier(&filed).title,
        "Citadel later"
    );
    let conflicts: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(details, '$.won') FROM audit_events \
         WHERE action = 'linear.conflict' ORDER BY seq",
    )
    .fetch_all(&stage.pool)
    .await
    .unwrap();
    assert_eq!(conflicts, ["linear", "citadel"]);

    // Back to the backlog is not a move the engine makes: Linear gets the state back.
    board
        .lock()
        .unwrap()
        .edit(&filed, |i| i.state_id = "st-0".to_owned());
    sync(&stage).await;
    let i = get_issue(&stage.pool, theirs).await.unwrap().unwrap();
    assert_eq!(i.state, IssueState::InProgress);
    let restored = board.lock().unwrap().by_identifier(&filed).state_id;
    assert_eq!(restored, "st-2", "In Progress again");
    let before = settled(&stage).await;
    sync(&stage).await;
    sync(&stage).await;
    assert_eq!(settled(&stage).await, before, "settled: no loop");
    let all = actions(&stage).await;
    for a in [
        "linear.imported",
        "linear.exported",
        "linear.pulled",
        "linear.pushed",
        "linear.conflict",
        "linear.state_refused",
    ] {
        assert!(all.iter().any(|x| x == a), "no {a} in {all:?}");
    }
}
