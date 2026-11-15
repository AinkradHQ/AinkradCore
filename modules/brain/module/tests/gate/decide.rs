//! The Review's one decision after the AI tidy (API minor 73): `POST /imports/{run}/commit` with
//! `{"keep": [...], "keep_unsorted": bool}` imports the kept rooms and refuses every other one in
//! the same call, merge targets and rooms the tidy moved items into included. The old per-room
//! Accept and Refuse still work for older Apps. Every name and text here is made up.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{Method, StatusCode};
use brain_model::item::hash_of;
use brain_module::Brain;
use serde_json::{Value, json};

use super::common::*;
use super::tidy::{Topics, it, ready, sample};

/// What the App shows: every proposal that is not merged away.
async fn visible(fx: &Fx, run: &str) -> Vec<Value> {
    proposals(fx, run)
        .await
        .into_iter()
        .filter(|p| p["state"] != "merged")
        .collect()
}

fn id_of(p: &[Value], prefix: &str) -> String {
    p.iter()
        .find(|c| c["name"].as_str().unwrap().starts_with(prefix))
        .unwrap_or_else(|| panic!("no room {prefix}: {p:?}"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn commit(fx: &Fx, run: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/imports/{run}/commit"),
        body,
    )
    .await
}

/// The tidy sample plus an Unsorted item no room claims; the tidy merged, moved and de-duplicated.
async fn tidied(fx: &Fx) -> String {
    let run = sample(fx).await;
    send(fx, &run, vec![it(31, "", 9, 31)]).await;
    finish(fx, &run).await;
    let v = ready(fx, &run).await;
    let s = &v["ai_tidy"]["summary"];
    assert_eq!(v["ai_tidy"]["state"], "applied", "{v}");
    for k in ["duplicates_merged", "rooms_merged", "items_moved"] {
        assert!(s[k].as_u64().unwrap() > 0, "{k}: {s}");
    }
    run
}

/// item id, title, text and proposal state of every staged item.
async fn staged(fx: &Fx, run: &str) -> Vec<(String, String, String, String)> {
    let st = staging_pool(fx, run).await;
    let rows = sqlx::query_as(
        "SELECT i.item_id, i.title, i.text, p.state FROM items i JOIN proposals p ON p.id = i.proposal ORDER BY i.item_id",
    )
    .fetch_all(&st)
    .await
    .unwrap();
    st.close().await;
    rows
}

async fn refused_hashes(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM brain_seen WHERE room = 'refused'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn one_call_imports_the_kept_rooms_and_refuses_and_wipes_every_other() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Topics::default())), 1).await;
    let run = tidied(&fx).await;
    let p = visible(&fx, &run).await;
    // The merge target and the room an Unsorted item moved into; Alpha and the rest go.
    let keep = [id_of(&p, "Pricing"), id_of(&p, "Delta")];
    let (s, v) = commit(
        &fx,
        &run,
        Some(json!({"keep": keep, "keep_unsorted": false})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "committed");
    let mut names: Vec<&str> = v["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{v}");
    assert!(
        names[0] == "Delta" && names[1].starts_with("Pricing"),
        "{names:?}"
    );
    // Every item of a merged-in room went with its target; nothing waits in a merged room.
    let rows = staged(&fx, &run).await;
    assert!(rows.iter().all(|r| r.3 != "merged"), "{rows:?}");
    // Everything not kept is refused and wiped, Unsorted too: only the hash stays.
    let refused: Vec<_> = rows.iter().filter(|r| r.3 == "refused").collect();
    assert!(refused.len() >= 9, "{rows:?}");
    assert!(
        refused.iter().all(|r| r.1 == "[refused]" && r.2.is_empty()),
        "{refused:?}"
    );
    assert!(
        rows.iter()
            .filter(|r| r.3 == "committed")
            .all(|r| !r.2.is_empty())
    );
    assert!(refused_hashes(&fx).await >= refused.len() as i64);
    let stored = everything_stored(&fx).await;
    assert!(
        !stored.contains("note 31") && !stored.contains("topic=9"),
        "Unsorted was deleted"
    );
}

#[tokio::test]
async fn keep_unsorted_leaves_its_items_waiting_and_a_second_call_changes_nothing() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Topics::default())), 1).await;
    let run = tidied(&fx).await;
    let alpha = id_of(&visible(&fx, &run).await, "Alpha");
    let body = json!({"keep": [alpha], "keep_unsorted": true});
    let (s, v) = commit(&fx, &run, Some(body.clone())).await;
    assert_eq!(
        (s, &v["state"]),
        (StatusCode::OK, &json!("committed")),
        "{v}"
    );
    let rows = staged(&fx, &run).await;
    let unsorted: Vec<_> = rows.iter().filter(|r| r.3 == "proposed").collect();
    assert!(
        !unsorted.is_empty() && unsorted.iter().all(|r| !r.2.is_empty()),
        "{rows:?}"
    );
    // Again (a retry after a timeout): a plain 409, nothing written twice.
    let (seen, stored) = (refused_hashes(&fx).await, everything_stored(&fx).await);
    let (s, v) = commit(&fx, &run, Some(body)).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("conflict")),
        "{v}"
    );
    assert_eq!(
        (refused_hashes(&fx).await, everything_stored(&fx).await),
        (seen, stored)
    );
}

#[tokio::test]
async fn a_bad_keep_is_refused_before_anything_changes() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Topics::default())), 1).await;
    let run = tidied(&fx).await;
    // The list never shows a room the tidy merged away; the App may still hold its old id.
    let st = staging_pool(&fx, &run).await;
    let merged: String =
        sqlx::query_scalar("SELECT id FROM proposals WHERE state = 'merged' LIMIT 1")
            .fetch_one(&st)
            .await
            .unwrap();
    st.close().await;
    let before = super::tidy::dump(&fx, &run).await;
    for keep in [json!(["unsorted"]), json!(["p-nope"]), json!([merged])] {
        let (s, v) = commit(&fx, &run, Some(json!({"keep": keep}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{keep}: {v}");
    }
    let (s, _) = commit(&fx, &run, Some(json!({"kept": []}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(super::tidy::dump(&fx, &run).await, before);
}

#[tokio::test]
async fn the_old_accept_refuse_and_commit_still_work_after_a_tidy() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Topics::default())), 1).await;
    let run = tidied(&fx).await;
    let p = visible(&fx, &run).await;
    for prefix in ["Pricing", "Delta"] {
        let path = format!("/imports/{run}/proposals/{}", id_of(&p, prefix));
        assert_eq!(
            ok(
                &fx,
                Method::PATCH,
                &path,
                Some(json!({"state": "accepted"}))
            )
            .await["state"],
            "accepted"
        );
    }
    for prefix in ["Alpha", "Gamma"] {
        let path = format!("/imports/{run}/proposals/{}/refuse", id_of(&p, prefix));
        assert_eq!(ok(&fx, Method::POST, &path, None).await["state"], "refused");
    }
    let path = "/imports/{run}/proposals/unsorted/refuse".replace("{run}", &run);
    assert_eq!(ok(&fx, Method::POST, &path, None).await["state"], "refused");
    let (s, v) = commit(&fx, &run, None).await;
    assert_eq!(
        (s, v["rooms"].as_array().unwrap().len()),
        (StatusCode::OK, 2),
        "{v}"
    );
}

/// The live run's size: 8,000 items of about 3 KB, 32 rooms, every tenth item a near-copy the tidy
/// merges. Prints how long each Review call takes (`--ignored --nocapture`); the App gives up at 20 s.
#[tokio::test]
#[ignore = "benchmark: cargo test --test gate bench -- --ignored --nocapture"]
async fn bench_review_calls_at_8000_items() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Topics::default())), 1).await;
    let run = start(&fx).await;
    let filler: String = (0..450).map(|w| format!("w{w} ")).collect();
    let mut items = vec![];
    let mut n = 0u32;
    for room in 0..32usize {
        let mut var = 0;
        for i in 0..250 {
            n += 1;
            if i % 10 != 9 {
                var += 1;
            }
            let mut x = it(n, &format!("/u/Dev/Room{room:02}x"), room, var);
            x["text"] = json!(format!("{} {filler}", x["text"].as_str().unwrap()));
            x["content_hash"] = json!(hash_of(x["text"].as_str().unwrap()));
            items.push(x);
        }
    }
    for chunk in items.chunks(200) {
        send(&fx, &run, chunk.to_vec()).await;
    }
    finish(&fx, &run).await;
    let t = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let v = ok(&fx, Method::GET, &format!("/imports/{run}/semantic"), None).await;
        if v["state"] != "pending" {
            println!("bench semantic+tidy {:?}: {}", t.elapsed(), v["ai_tidy"]);
            break;
        }
    }
    async fn timed(fx: &Fx, what: &str, m: Method, path: &str, body: Option<Value>) -> Value {
        let t = Instant::now();
        let (s, v) = call(fx, &fx.admin, m, path, body).await;
        println!("bench {what}: {:?} ({s})", t.elapsed());
        assert!(s.is_success(), "{what}: {v}");
        v
    }
    let list = timed(
        &fx,
        "room list",
        Method::GET,
        &format!("/imports/{run}/proposals"),
        None,
    )
    .await;
    let ids: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["state"] != "merged" && p["id"] != "unsorted")
        .map(|p| p["id"].as_str().unwrap().to_owned())
        .collect();
    let path = format!("/imports/{run}/proposals/{}/items?limit=100", ids[0]);
    timed(&fx, "open a room", Method::GET, &path, None).await;
    let path = format!("/imports/{run}/proposals/{}/refuse", ids[1]);
    timed(&fx, "refuse one room", Method::POST, &path, None).await;
    timed(
        &fx,
        "re-sort",
        Method::POST,
        &format!("/imports/{run}/regroup"),
        None,
    )
    .await;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let v = ok(&fx, Method::GET, &format!("/imports/{run}/semantic"), None).await;
        if v["state"] != "pending" {
            break;
        }
    }
    let list = ok(&fx, Method::GET, &format!("/imports/{run}/proposals"), None).await;
    let open: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["state"] != "merged" && p["id"] != "unsorted")
        .map(|p| p["id"].as_str().unwrap().to_owned())
        .collect();
    let half = open.len() / 2;
    let t = Instant::now();
    for id in &open[..half] {
        let path = format!("/imports/{run}/proposals/{id}");
        ok(
            &fx,
            Method::PATCH,
            &path,
            Some(json!({"state": "accepted"})),
        )
        .await;
    }
    println!("bench accept {half} rooms one by one: {:?}", t.elapsed());
    timed(
        &fx,
        "commit",
        Method::POST,
        &format!("/imports/{run}/commit"),
        None,
    )
    .await;
}
