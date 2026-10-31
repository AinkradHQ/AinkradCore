//! The Linear client against the fake Linear.

use super::*;
use crate::fake;

#[tokio::test]
async fn reads_the_team_and_creates_updates_and_lists_issues_since_a_cursor() {
    let (api, board) = fake::linear("lin_api_key", "team-1", &["Developer 1"]).await;
    let lin = Linear::new(client(), &api, Secret::new("lin_api_key"));
    let team = lin.team("team-1").await.unwrap();
    let kinds: Vec<&str> = team.states.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "backlog",
            "unstarted",
            "started",
            "started",
            "completed",
            "canceled"
        ]
    );
    assert_eq!(team.members, [("u-0".to_owned(), "Developer 1".to_owned())]);

    let todo = team.states[1].id.clone();
    let made = Changes {
        title: Some("Export".to_owned()),
        description: Some("As CSV.".to_owned()),
        state_id: Some(todo),
        assignee_id: None,
    };
    let created = lin.create("team-1", &made).await.unwrap();
    assert_eq!(
        (created.identifier.as_str(), created.state.kind.as_str()),
        ("ENG-1", "unstarted")
    );
    let cursor = created.updated_at.clone();
    assert!(
        lin.issues_since("team-1", Some(&cursor))
            .await
            .unwrap()
            .is_empty()
    );

    let assign = Changes {
        assignee_id: Some("u-0".to_owned()),
        ..Changes::default()
    };
    let updated = lin.update(&created.id, &assign).await.unwrap();
    assert_eq!(
        updated.assignee,
        Some(("u-0".to_owned(), "Developer 1".to_owned()))
    );
    board.lock().unwrap().file("Filed in Linear", "Backlog");
    let since = lin.issues_since("team-1", Some(&cursor)).await.unwrap();
    let ids: Vec<&str> = since.iter().map(|i| i.identifier.as_str()).collect();
    assert_eq!(ids, ["ENG-1", "ENG-2"], "oldest change first");
    assert_eq!(lin.issues_since("team-1", None).await.unwrap().len(), 2);
    assert_eq!(
        board.lock().unwrap().mutations,
        ["IssueCreate", "IssueUpdate"]
    );

    let gone = lin.update("lin-99", &assign).await.unwrap_err();
    assert_eq!(gone.to_string(), "HTTP 200: Entity not found");
    let wrong = Linear::new(client(), &api, Secret::new("lin_wr0ng"));
    let e = wrong.team("team-1").await.unwrap_err();
    assert!(matches!(e, Error::Http { status: 400, .. }), "{e}");
    assert!(!format!("{e:?}").contains("wr0ng"));
}

/// An endpoint that always says there is another page cannot keep a pass reading for ever.
#[tokio::test]
async fn a_team_that_never_ends_is_refused_after_the_page_cap() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let pages = Arc::new(AtomicUsize::new(0));
    let seen = pages.clone();
    let app = axum::Router::new().fallback(move || {
        seen.fetch_add(1, Ordering::SeqCst);
        async {
            axum::Json(serde_json::json!({"data": {"issues": {"nodes": [],
                "pageInfo": {"hasNextPage": true, "endCursor": "c"}}}}))
        }
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    let policy = crate::guard::Policy::new([]).with_test_origin(addr);
    let lin = Linear::new(policy.client(), &format!("http://{addr}"), Secret::new("k"));
    let err = lin.issues_since("team-1", None).await.unwrap_err();
    assert!(err.to_string().contains("pages"), "{err}");
    assert_eq!(pages.load(Ordering::SeqCst), MAX_PAGES);
}
