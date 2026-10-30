//! E9.4's acceptance against a fake Linear: issues and edits round-trip both ways, a field both
//! sides changed goes to the later writer (audited), a state the engine refuses is put back in
//! Linear, nothing either side wrote echoes back; and the call policy and the credential rules
//! hold for Linear as for the forges.

mod common;
mod forge_seed;
mod gov_seed;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core_server::api::v1::BY;
use ainkrad_providers::fake;
use ainkrad_providers::guard::Policy;
use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use citadel_module::domain::work::{IssueId, IssueState, IssueTransition, NextActor};
use citadel_module::forge::{Runtime, linear_sync};
use citadel_module::store::linear::{ProjectLinear, set_project_linear};
use citadel_module::store::work::{get_issue, list_issues, transition_issue, update_issue};
use forge_seed::*;

const LINEAR_SECRET: &str = "citadel.linear";
const LINEAR_KEY: &str = "lin_key";

struct Lin {
    fx: Fx,
    s: Seed,
    rt: Arc<Runtime>,
    sealer: Arc<ainkrad_core_server::ops::secretbox::SecretBox>,
    api: String,
    board: fake::Shared<fake::Board>,
}

async fn lin() -> Lin {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "AAA").await;
    let sealer = broker(&fx).await;
    add_secret(&fx, &sealer, LINEAR_SECRET, LINEAR_KEY).await;
    let (api, board) = fake::linear(LINEAR_KEY, "team-1", &["Dev A"]).await;
    let policy = Policy::new([]).with_test_origin(addr_of(&api));
    let rt = Runtime::with_policy(fx.app.pool.clone(), sealer.clone(), policy);
    Lin {
        fx,
        s,
        rt,
        sealer,
        api,
        board,
    }
}

async fn link(l: &Lin, api: &str, secret: &str) {
    let config = ProjectLinear {
        project_id: l.s.project,
        team_id: "team-1".to_owned(),
        api_url: api.to_owned(),
        secret: secret.to_owned(),
        cursor: None,
    };
    assert!(
        set_project_linear(&l.fx.app.pool, &config, BY)
            .await
            .unwrap()
    );
}

async fn sync(l: &Lin) {
    linear_sync(&l.rt).await.unwrap();
}

async fn retitle(l: &Lin, issue: IssueId, title: &str) {
    let mut i = get_issue(&l.fx.app.pool, issue).await.unwrap().unwrap();
    i.title = title.to_owned();
    assert!(update_issue(&l.fx.app.pool, &i).await.unwrap());
}

async fn actions(l: &Lin) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'citadel.linear.%' ORDER BY seq",
    )
    .fetch_all(&l.fx.app.pool)
    .await
    .unwrap()
}

/// What a sync wrote either way: Linear mutations and its own audit rows.
async fn settled(l: &Lin) -> (usize, i64) {
    let b = l.board.lock().unwrap().mutations.len();
    let a: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action LIKE 'citadel.linear.%'",
    )
    .fetch_one(&l.fx.app.pool)
    .await
    .unwrap();
    (b, a)
}

#[tokio::test]
async fn edits_round_trip_both_ways_and_nothing_echoes() {
    let l = lin().await;
    let pool = &l.fx.app.pool;
    link(&l, &l.api, LINEAR_SECRET).await;

    // First pass: Linear's issue comes in, Citadel's goes out.
    let ours = l.s.issue;
    let filed = l.board.lock().unwrap().file("Filed in Linear", "Backlog");
    sync(&l).await;
    let issues = list_issues(pool, l.s.project).await.unwrap();
    let theirs = issues
        .iter()
        .find(|i| i.title == "Filed in Linear")
        .unwrap();
    assert_eq!(theirs.state, IssueState::Backlog);
    let theirs = theirs.id;
    let exported = l.board.lock().unwrap().by_identifier("ENG-2");
    assert_eq!(exported.title, "Ship it");
    assert_eq!(exported.state_id, l.board.lock().unwrap().state_id("Todo"));
    assert_eq!(l.board.lock().unwrap().mutations, ["IssueCreate"]);
    let before = settled(&l).await;
    sync(&l).await;
    sync(&l).await;
    assert_eq!(
        settled(&l).await,
        before,
        "no echo: nothing written either way"
    );

    // Linear to Citadel: a rename and a start, through the engine.
    l.board.lock().unwrap().edit(&filed, |i| {
        i.title = "Renamed in Linear".to_owned();
        i.state_id = "st-2".to_owned();
    });
    sync(&l).await;
    let i = get_issue(pool, theirs).await.unwrap().unwrap();
    assert_eq!(
        (i.title.as_str(), i.state),
        ("Renamed in Linear", IssueState::InProgress)
    );
    assert_eq!(
        l.board.lock().unwrap().mutations.len(),
        1,
        "nothing pushed back"
    );

    // Citadel to Linear: a rename and an assignee Linear knows by name.
    retitle(&l, ours, "Renamed in Citadel").await;
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(l.s.agent),
    };
    transition_issue(pool, ours, &to_dev, BY).await.unwrap();
    sync(&l).await;
    let pushed = l.board.lock().unwrap().by_identifier("ENG-2");
    assert_eq!(pushed.title, "Renamed in Citadel");
    assert_eq!(pushed.assignee_id.as_deref(), Some("u-0"), "Dev A");
    let before = settled(&l).await;
    sync(&l).await;
    assert_eq!(settled(&l).await, before, "no echo of its own push");

    // Both rename it: the later writer wins, either way round, and it is audited.
    retitle(&l, theirs, "Citadel first").await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    l.board
        .lock()
        .unwrap()
        .edit(&filed, |i| i.title = "Linear later".to_owned());
    sync(&l).await;
    assert_eq!(
        get_issue(pool, theirs).await.unwrap().unwrap().title,
        "Linear later"
    );
    l.board
        .lock()
        .unwrap()
        .edit(&filed, |i| i.title = "Linear first".to_owned());
    tokio::time::sleep(Duration::from_millis(5)).await;
    retitle(&l, theirs, "Citadel later").await;
    sync(&l).await;
    assert_eq!(
        get_issue(pool, theirs).await.unwrap().unwrap().title,
        "Citadel later"
    );
    assert_eq!(
        l.board.lock().unwrap().by_identifier(&filed).title,
        "Citadel later"
    );
    let conflicts: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(details, '$.won') FROM audit_events \
         WHERE action = 'citadel.linear.conflict' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(conflicts, ["linear", "citadel"]);

    // Back to the backlog is not a move the engine makes: Linear gets the state back.
    l.board
        .lock()
        .unwrap()
        .edit(&filed, |i| i.state_id = "st-0".to_owned());
    sync(&l).await;
    assert_eq!(
        get_issue(pool, theirs).await.unwrap().unwrap().state,
        IssueState::InProgress
    );
    assert_eq!(
        l.board.lock().unwrap().by_identifier(&filed).state_id,
        "st-2"
    );
    let before = settled(&l).await;
    sync(&l).await;
    sync(&l).await;
    assert_eq!(settled(&l).await, before, "settled: no loop");
    let all = actions(&l).await;
    for a in [
        "imported",
        "exported",
        "pulled",
        "pushed",
        "conflict",
        "state_refused",
    ] {
        let full = format!("citadel.linear.{a}");
        assert!(all.contains(&full), "no {full} in {all:?}");
    }
}

#[tokio::test]
async fn a_linear_url_off_the_policy_is_never_called_and_opens_no_credential() {
    let mut l = lin().await;
    l.rt = Runtime::new(l.fx.app.pool.clone(), l.sealer.clone());
    link(&l, &l.api, LINEAR_SECRET).await;
    sync(&l).await;
    assert!(l.board.lock().unwrap().mutations.is_empty());
    let used: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'secret.used'")
            .fetch_one(&l.fx.app.pool)
            .await
            .unwrap();
    assert_eq!(used, 0, "the refused link opened nothing");
}

/// A writer of captured log lines.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Log {
    type Writer = Log;
    fn make_writer(&'a self) -> Log {
        self.clone()
    }
}

#[tokio::test]
async fn a_token_linear_echoes_is_in_no_log_and_not_in_the_database() {
    let mut l = lin().await;
    let echo = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let app = Router::new().fallback(|h: HeaderMap| async move {
            let auth = h
                .get(header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"message": format!("denied {auth}")})),
            )
        });
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        addr
    };
    l.rt = Runtime::with_policy(
        l.fx.app.pool.clone(),
        l.sealer.clone(),
        Policy::new([]).with_test_origin(echo),
    );
    link(&l, &format!("http://{echo}"), LINEAR_SECRET).await;
    let log = Log::default();
    let sub = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    {
        let _guard = tracing::subscriber::set_default(sub);
        sync(&l).await;
    }
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("Linear sync failed"),
        "the failure is logged: {text:?}"
    );
    assert!(
        text.contains("<redacted>") && !text.contains(LINEAR_KEY),
        "{text}"
    );
    assert!(
        !contains(&db_bytes(&l.fx).await, LINEAR_KEY),
        "the token is on disk"
    );
}
