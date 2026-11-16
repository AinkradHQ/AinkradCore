//! E7-1: a room's FTS5 index. It is rebuilt from the room, never the source of truth.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::common::*;

const ALPHA: &str = "/h/Projects/Alpha/a";

async fn room_of(fx: &Fx, texts: &[(&str, &str)]) -> String {
    let run = start(fx).await;
    let items = texts
        .iter()
        .enumerate()
        .map(|(i, (t, x))| item(i as u32 + 1, ALPHA, t, x))
        .collect();
    send(fx, &run, items).await;
    finish(fx, &run).await;
    let id = proposals(fx, &run).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        fx,
        Method::PATCH,
        &format!("/imports/{run}/proposals/{id}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    let room =
        ok(fx, Method::POST, &format!("/imports/{run}/commit"), None).await["rooms"][0]["room"]
            .as_str()
            .unwrap()
            .to_owned();
    ok(fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    room
}

async fn search(fx: &Fx, room: &str, q: &str) -> Value {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::GET,
        &format!("/rooms/{room}/search?q={q}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

fn index_file(fx: &Fx, room: &str) -> std::path::PathBuf {
    brain_module::files::index_path(&brain_module::files::root(&fx.app), room)
}

const DOCS: &[(&str, &str)] = &[
    ("Billing", "the invoice export fails on large invoices"),
    (
        "Deploy",
        "deploy the invoice service with the new migration",
    ),
    ("Notes", "lunch plans and nothing else"),
];

#[tokio::test]
async fn search_finds_the_words_best_first_and_a_rebuilt_index_gives_the_same_results() {
    let fx = fx().await;
    let room = room_of(&fx, DOCS).await;
    let hits = search(&fx, &room, "invoice").await;
    assert_eq!(hits["hits"].as_array().unwrap().len(), 2, "{hits}");
    assert!(
        hits["hits"][0]["snippet"]
            .as_str()
            .unwrap()
            .contains("«invoice»")
    );
    assert_eq!(
        search(&fx, &room, "lunch").await["hits"][0]["title"],
        "Notes"
    );
    let before = [
        search(&fx, &room, "invoice").await,
        search(&fx, &room, "invoice%20service").await,
        search(&fx, &room, "migration").await,
    ];
    // Delete the index: the next search rebuilds it from the room and answers identically.
    std::fs::remove_file(index_file(&fx, &room)).unwrap();
    assert!(!index_file(&fx, &room).exists());
    let after = [
        search(&fx, &room, "invoice").await,
        search(&fx, &room, "invoice%20service").await,
        search(&fx, &room, "migration").await,
    ];
    assert!(index_file(&fx, &room).exists());
    assert_eq!(before, after);
    assert_eq!(after[1]["hits"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn the_index_is_encrypted_and_a_closed_room_cannot_be_searched() {
    let fx = fx().await;
    let room = room_of(&fx, DOCS).await;
    search(&fx, &room, "lunch").await;
    let raw = std::fs::read(index_file(&fx, &room)).unwrap();
    assert!(!raw.starts_with(b"SQLite format 3"));
    assert!(!String::from_utf8_lossy(&raw).contains("lunch plans"));
    // A room that was never opened has no handle.
    let other = {
        let run = start(&fx).await;
        send(
            &fx,
            &run,
            vec![item(9, "/h/Projects/Beta/b", "b", "beta text")],
        )
        .await;
        finish(&fx, &run).await;
        let id = proposals(&fx, &run)
            .await
            .iter()
            .find(|p| p["name"] == "Beta")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        ok(
            &fx,
            Method::PATCH,
            &format!("/imports/{run}/proposals/{id}"),
            Some(json!({"state": "accepted"})),
        )
        .await;
        ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await["rooms"][0]["room"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/rooms/{other}/search?q=beta"),
        None,
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("room_closed"))
    );
    let (s, _) = call(&fx, &fx.admin, Method::GET, "/rooms/nope/search?q=x", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn search_input_is_words_never_syntax_and_the_index_follows_new_sources() {
    let fx = fx().await;
    let room = room_of(&fx, DOCS).await;
    // FTS5 syntax characters are only separators.
    for q in [
        "invoice%20AND",
        "%22invoice",
        "invoice*",
        "NEAR(",
        "col%3Atitle",
    ] {
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::GET,
            &format!("/rooms/{room}/search?q={q}"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{q}");
    }
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/rooms/{room}/search?q=%20%2B"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(search(&fx, &room, "kubernetes").await["hits"], json!([]));
    // A later run adds a source: the stale index is rebuilt by the next search.
    let run = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"kind": "incremental", "sources": ["claude_code"]})),
    )
    .await["run"]
        .as_str()
        .unwrap()
        .to_owned();
    send(
        &fx,
        &run,
        vec![item(7, ALPHA, "K8s", "kubernetes rollout notes")],
    )
    .await;
    finish(&fx, &run).await;
    assert_eq!(
        search(&fx, &room, "kubernetes").await["hits"][0]["title"],
        "K8s"
    );
}

/// The Items tab before any distillation: the newest sources, newest first, with no records yet.
#[tokio::test]
async fn latest_lists_the_newest_sources_and_says_nothing_is_distilled() {
    let fx = fx().await;
    let room = room_of(&fx, DOCS).await;
    let v = ok(
        &fx,
        Method::GET,
        &format!("/rooms/{room}/latest?limit=2"),
        None,
    )
    .await;
    assert_eq!(v["records"], 0, "{v}");
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{v}");
    // `item(n)` starts on day 1 + n: the last DOCS item is the newest.
    assert_eq!(items[0]["title"], DOCS[DOCS.len() - 1].0, "{v}");
    assert_eq!(items[1]["title"], DOCS[DOCS.len() - 2].0, "{v}");
    assert_eq!(items[0]["type"], "source");
    assert_eq!(items[0]["source_kind"], "claude_code");
    assert!(
        items[0]["started_at"].as_str() > items[1]["started_at"].as_str(),
        "{v}"
    );
    let all = ok(&fx, Method::GET, &format!("/rooms/{room}/latest"), None).await;
    assert_eq!(all["items"].as_array().unwrap().len(), DOCS.len());
    // A closed room and an unknown one answer as search does.
    let closed =
        committed_room_named(&fx, "Beta", &[("Other", "a different room's only note")]).await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/rooms/{closed}/latest"),
        None,
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("room_closed"))
    );
    let (s, _) = call(&fx, &fx.admin, Method::GET, "/rooms/nope/latest", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// Sub-agent transcripts and scratch-path prompts are refused at intake; one first prompt shows once.
#[tokio::test]
async fn sub_agent_prompts_are_skipped_and_one_first_prompt_lists_once() {
    let fx = fx().await;
    let run = start(&fx).await;
    let mut sub = item(1, ALPHA, "Fix the made-up build", "sub-agent text");
    sub["origin"]["path"] = json!("/synthetic/projects/p/s9/subagents/agent-x.jsonl");
    let scratch = item(
        2,
        ALPHA,
        "Read and follow exactly: /private/tmp/made-up/t.md",
        "scratch",
    );
    let first = item(3, ALPHA, "Land these, in order", "first run");
    let again = item(4, ALPHA, "Land  these, in order (part 1)", "second run");
    let other = item(5, ALPHA, "Write the made-up docs", "docs");
    let v = send(&fx, &run, vec![sub, scratch, first, again, other]).await;
    let st: Vec<_> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["status"].as_str().unwrap())
        .collect();
    assert_eq!(
        st,
        ["refused", "refused", "stored", "stored", "stored"],
        "{v}"
    );
    finish(&fx, &run).await;
    let id = proposals(&fx, &run).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{run}/proposals/{id}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    let room =
        ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await["rooms"][0]["room"]
            .as_str()
            .unwrap()
            .to_owned();
    ok(&fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    let v = ok(&fx, Method::GET, &format!("/rooms/{room}/latest"), None).await;
    let titles: Vec<_> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles.len(), 2, "{v}");
    assert!(
        titles.contains(&"Land  these, in order (part 1)"),
        "the newest copy stays: {v}"
    );
}
