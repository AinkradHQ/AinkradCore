//! E5-2: the Jira and GitHub collectors, through canned reads (no network, no token). They are off
//! by default, read only, turn tracker keys and the org into signals, and move their cursor only
//! when the run is committed.

use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use brain_module::Brain;
use brain_module::collectors::{Fetch, Fut};
use serde_json::{Value, json};

use super::common::*;

#[derive(Default)]
struct Fake {
    seen: Mutex<Vec<(String, Value)>>,
    refuse: Mutex<Option<String>>,
}

impl Fetch for Fake {
    fn call<'a>(&'a self, op: &'a str, args: Value) -> Fut<'a> {
        self.seen
            .lock()
            .unwrap()
            .push((op.to_owned(), args.clone()));
        let refuse = self.refuse.lock().unwrap().clone();
        Box::pin(async move {
            if let Some(e) = refuse {
                return Err(e);
            }
            Ok(match op {
                "jira.search_issues" => json!({"isLast": true, "issues": [
                    {"key": "KAN-476", "fields": {"summary": "Brain import", "status": {"name": "In Progress"},
                        "issuetype": {"name": "Epic"}, "reporter": {"displayName": "Ahmed"},
                        "created": "2026-11-01T08:00:00.000+0000", "updated": "2026-11-10T09:00:00.000+0000",
                        "description": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Import everything safely."}]}]}}},
                    {"key": "KAN-500", "fields": {"summary": "Inbox", "status": {"name": "To Do"},
                        "created": "2026-11-02T08:00:00.000+0000", "updated": "2026-11-11T09:00:00.000+0000"}}]}),
                "github.list_prs" if args["query"]["page"] == 1 => json!([
                    {"number": 12, "title": "Add the claim", "state": "closed", "merged_at": "2026-11-11T10:00:00Z",
                     "user": {"login": "ahmed"}, "base": {"ref": "development"}, "body": "Claims a room.",
                     "created_at": "2026-11-10T10:00:00Z", "updated_at": "2026-11-11T10:00:00Z",
                     "html_url": "https://github.com/acme/app/pull/12"}]),
                "github.list_pr_reviews" => json!([
                    {"user": {"login": "bashar"}, "state": "APPROVED", "body": "Looks right."}]),
                _ => json!([]),
            })
        })
    }
}

async fn fx_fake() -> (Fx, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let fx = fx_with(Brain::with_fetch(fake.clone()), 1).await;
    (fx, fake)
}

async fn enable(fx: &Fx, id: &str, roots: &[&str]) {
    ok(
        fx,
        Method::PUT,
        &format!("/sources/{id}"),
        Some(json!({"device": "core", "kind": id, "enabled": true, "roots": roots})),
    )
    .await;
}

async fn sync(fx: &Fx, source: &str) -> Value {
    ok(fx, Method::POST, "/sync", Some(json!({"source": source}))).await
}

async fn cursor(fx: &Fx, id: &str) -> Value {
    let s = ok(fx, Method::GET, "/sources", None).await;
    s.as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == id)
        .unwrap()["cursor"]
        .clone()
}

async fn accept_and_commit(fx: &Fx, run: &str) {
    for p in proposals(fx, run).await {
        let id = p["id"].as_str().unwrap();
        ok(
            fx,
            Method::PATCH,
            &format!("/imports/{run}/proposals/{id}"),
            Some(json!({"state": "accepted"})),
        )
        .await;
    }
    ok(fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
}

#[tokio::test]
async fn the_connection_collectors_are_off_until_switched_on() {
    let (fx, fake) = fx_fake().await;
    let list = ok(&fx, Method::GET, "/sources", None).await;
    for id in ["jira", "github"] {
        let s = list
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == id)
            .unwrap();
        assert_eq!(
            (s["enabled"].as_bool(), s["device"].as_str()),
            (Some(false), Some("core"))
        );
        assert_eq!(sync(&fx, id).await["idle"], "disabled");
    }
    assert!(fake.seen.lock().unwrap().is_empty(), "nothing was read");
}

#[tokio::test]
async fn jira_issues_become_items_with_tracker_signals_and_the_cursor_moves_on_commit() {
    let (fx, fake) = fx_fake().await;
    enable(&fx, "jira", &["KAN"]).await;
    let r = sync(&fx, "jira").await;
    assert_eq!(
        (r["found"].as_u64(), r["stored"].as_u64()),
        (Some(2), Some(2)),
        "{r}"
    );
    let run = r["run"].as_str().unwrap().to_owned();
    // Tracker keys are the signals of the proposal; the text is the issue, the description included.
    let p = proposals(&fx, &run).await;
    assert!(
        p.iter().any(|c| c["signals"].to_string().contains("KAN")),
        "{p:?}"
    );
    assert_eq!(fake.seen.lock().unwrap()[0].1["project"], "KAN");
    let list = ok(&fx, Method::GET, "/sources", None).await;
    let jira = list
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "jira")
        .unwrap();
    assert_eq!(
        (jira["items"].as_i64(), jira["runner"].is_null()),
        (Some(2), true)
    );
    // Until the run is committed the source's cursor stays; a second sync takes nothing twice.
    assert_eq!(cursor(&fx, "jira").await, json!({}));
    assert_eq!(sync(&fx, "jira").await["idle"], "nothing_new");
    accept_and_commit(&fx, &run).await;
    let newest = unix("2026-11-11T09:00:00Z");
    assert_eq!(cursor(&fx, "jira").await["projects"]["KAN"], newest);
    // The issue text reached the room.
    assert!(
        everything_stored(&fx)
            .await
            .contains("Import everything safely.")
    );
}

fn unix(iso: &str) -> i64 {
    ainkrad_core_server::scheduler::unix_secs(iso).unwrap()
}

#[tokio::test]
async fn github_pull_requests_carry_their_reviews_and_the_org() {
    let (fx, fake) = fx_fake().await;
    assert_eq!(sync(&fx, "github").await["idle"], "disabled");
    enable(&fx, "github", &[]).await;
    assert_eq!(sync(&fx, "github").await["idle"], "no_repositories");
    enable(&fx, "github", &["acme/app"]).await;
    let r = sync(&fx, "github").await;
    assert_eq!(r["stored"], 1, "{r}");
    let run = r["run"].as_str().unwrap().to_owned();
    let p = proposals(&fx, &run).await;
    assert!(
        p.iter()
            .any(|c| c["name"] == "app" || c["signals"].to_string().contains("acme")),
        "{p:?}"
    );
    accept_and_commit(&fx, &run).await;
    let all = everything_stored(&fx).await;
    assert!(
        all.contains("acme/app#12") && all.contains("State: merged"),
        "{all}"
    );
    assert!(all.contains("bashar (APPROVED): Looks right."));
    // A read of the same page again finds nothing past the cursor, and no write was ever asked.
    assert_eq!(sync(&fx, "github").await["idle"], "nothing_new");
    let ops: Vec<String> = fake
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(o, _)| o.clone())
        .collect();
    assert!(
        ops.iter()
            .all(|o| o.starts_with("github.list_") || o.starts_with("jira.search")),
        "{ops:?}"
    );
}

#[tokio::test]
async fn no_connection_is_idle_and_a_broken_one_is_an_error_not_a_hang() {
    let (fx, fake) = fx_fake().await;
    enable(&fx, "jira", &[]).await;
    *fake.refuse.lock().unwrap() = Some("not_granted: no connection grants this".to_owned());
    assert_eq!(sync(&fx, "jira").await["idle"], "no_connection");
    *fake.refuse.lock().unwrap() = Some("upstream_error: the service failed".to_owned());
    let (st, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/sync",
        Some(json!({"source": "jira"})),
    )
    .await;
    assert_eq!(
        (st, v["code"].as_str()),
        (StatusCode::BAD_GATEWAY, Some("connection_error"))
    );
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/sync",
        Some(json!({"source": "linear"})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_import_runs")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(runs, 0);
}
