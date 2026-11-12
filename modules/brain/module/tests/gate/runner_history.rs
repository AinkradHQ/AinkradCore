//! E5-3 (Core half): a runner's harness history as items. Off per runner until switched on; the
//! cursor moves when the run is committed; a restricted path the runner should never send is
//! still defused at intake. The runner's own reading is tested in `ainkrad-runner`.

use std::sync::{Arc, Mutex};

use ainkrad_proto::v2::{HistoryChunk, HistoryItem, HistoryRead};
use axum::http::Method;
use brain_module::Brain;
use brain_module::collectors::{HistFut, RunnerHistory};
use serde_json::{Value, json};

use super::common::*;

const SOURCE: &str = "runner-d_abc";

#[derive(Default)]
struct Fake {
    asked: Mutex<Vec<(String, HistoryRead)>>,
    chunks: Mutex<Vec<Result<HistoryChunk, String>>>,
}

impl RunnerHistory for Fake {
    fn read<'a>(&'a self, runner: &'a str, req: HistoryRead) -> HistFut<'a> {
        self.asked.lock().unwrap().push((runner.to_owned(), req));
        let next = self.chunks.lock().unwrap().remove(0);
        Box::pin(async move { next })
    }
}

fn part(session: &str, path: &str, first: u64, last: u64, text: &str) -> HistoryItem {
    HistoryItem {
        session: session.to_owned(),
        project: Some("/Users/x/Projects/Alpha".to_owned()),
        path: path.to_owned(),
        title: "Fix the build".to_owned(),
        text: format!("Claude Code session {session}, entries {first}-{last}\n\n{text}"),
        started_at: "2026-11-12T08:00:00.000Z".to_owned(),
        ended_at: Some("2026-11-12T08:05:00.000Z".to_owned()),
        first,
        last,
    }
}

fn chunk(items: Vec<HistoryItem>, more: bool) -> Result<HistoryChunk, String> {
    let cursor = items.iter().map(|i| (i.session.clone(), i.last)).collect();
    Ok(HistoryChunk {
        items,
        cursor,
        skipped: vec![],
        more,
    })
}

async fn fx_fake(chunks: Vec<Result<HistoryChunk, String>>) -> (Fx, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    *fake.chunks.lock().unwrap() = chunks;
    (fx_with(Brain::with_history(fake.clone()), 1).await, fake)
}

async fn put(fx: &Fx, enabled: Option<bool>) -> Value {
    ok(
        fx,
        Method::PUT,
        &format!("/sources/{SOURCE}"),
        Some(json!({"device": "ignored", "kind": "claude_code", "enabled": enabled})),
    )
    .await
}

async fn sync(fx: &Fx) -> Value {
    ok(fx, Method::POST, "/sync", Some(json!({"source": SOURCE}))).await
}

#[tokio::test]
async fn a_runners_history_is_off_until_switched_on_and_its_cursor_moves_on_commit() {
    let (fx, fake) = fx_fake(vec![
        chunk(
            vec![part(
                "s1",
                "claude/-p/s1.jsonl",
                1,
                4,
                "User: hi\n\nAssistant: hello",
            )],
            true,
        ),
        chunk(
            vec![part("s2", "claude/-p/s2.jsonl", 1, 2, "User: more")],
            false,
        ),
    ])
    .await;
    // Off by default, whatever else the caller says; the source belongs to that runner.
    let v = put(&fx, None).await;
    assert_eq!(
        (
            v["enabled"].as_bool(),
            v["device"].as_str(),
            v["kind"].as_str()
        ),
        (Some(false), Some("d_abc"), Some("claude_code"))
    );
    assert_eq!(sync(&fx).await["idle"], "disabled");
    assert!(
        fake.asked.lock().unwrap().is_empty(),
        "a switched-off runner is never asked"
    );
    put(&fx, Some(true)).await;
    let r = sync(&fx).await;
    assert_eq!(
        (r["found"].as_u64(), r["stored"].as_u64()),
        (Some(2), Some(2)),
        "{r}"
    );
    // Two chunks were asked for (the first said there is more), claude only, the second after the first's cursor.
    let asked = fake.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 2);
    assert_eq!(
        (asked[0].0.as_str(), asked[0].1.harness.as_str()),
        ("d_abc", "claude")
    );
    assert_eq!(asked[1].1.cursor["s1"], 4);
    // Until the run is committed the source's cursor stays.
    let run = r["run"].as_str().unwrap().to_owned();
    let cursor_of = |v: &Value| {
        v.as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == SOURCE)
            .unwrap()["cursor"]
            .clone()
    };
    assert_eq!(
        cursor_of(&ok(&fx, Method::GET, "/sources", None).await),
        json!({})
    );
    for p in proposals(&fx, &run).await {
        let id = p["id"].as_str().unwrap();
        ok(
            &fx,
            Method::PATCH,
            &format!("/imports/{run}/proposals/{id}"),
            Some(json!({"state": "accepted"})),
        )
        .await;
    }
    ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
    assert_eq!(
        cursor_of(&ok(&fx, Method::GET, "/sources", None).await),
        json!({"sessions": {"s1": 4, "s2": 2}})
    );
    assert!(everything_stored(&fx).await.contains("Assistant: hello"));
}

#[tokio::test]
async fn a_runner_that_did_not_switch_sharing_on_is_idle_and_a_restricted_path_is_defused() {
    let (fx, _fake) = fx_fake(vec![Err("not_offered".to_owned())]).await;
    put(&fx, Some(true)).await;
    assert_eq!(sync(&fx).await["idle"], "no_connection");

    // Even a runner that sent a restricted path (it must not) gets a pointer, never the text.
    let (fx, _fake) = fx_fake(vec![chunk(
        vec![part(
            "s9",
            "claude/-Users-x-contracts-nda/s9.jsonl",
            1,
            1,
            "User: THE CONTRACT TEXT",
        )],
        false,
    )])
    .await;
    put(&fx, Some(true)).await;
    let r = sync(&fx).await;
    let run = r["run"].as_str().unwrap().to_owned();
    for p in proposals(&fx, &run).await {
        let id = p["id"].as_str().unwrap();
        ok(
            &fx,
            Method::PATCH,
            &format!("/imports/{run}/proposals/{id}"),
            Some(json!({"state": "accepted"})),
        )
        .await;
    }
    ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
    assert!(!everything_stored(&fx).await.contains("THE CONTRACT TEXT"));
}

#[test]
fn the_runner_and_the_brain_agree_on_what_is_restricted() {
    for path in [
        "claude/-Users-x-contracts-nda/s.jsonl",
        "/Users/x/Projects/Alpha/.env",
        "/Users/x/Projects/Alpha/.env.local",
        "/Users/x/keys/server.pem",
        "/Users/x/Projects/Alpha/src/main.rs",
        "/Users/x/agreements/a.md",
        "/Users/x/.ssh/id_ed25519",
        "/Users/x/Projects/Alpha/contracts",
        "claude/Users/x/Projects/Alpha/s1.jsonl",
        "",
    ] {
        assert_eq!(
            ainkrad_proto::v2::restricted_path(path),
            brain_model::rules::restricted_path(path),
            "{path}"
        );
    }
}
