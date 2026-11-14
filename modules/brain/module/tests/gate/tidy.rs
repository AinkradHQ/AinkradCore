//! The AI tidy of Review with a fake embedder: a text `topic=K var=V` is the unit vector
//! `cos20° · e_K + sin20° · e_(32+V)`. Two items of one topic score 0.88 (not near-copies), the same
//! `(K, V)` scores 1 (a near-copy), two 3-item rooms of one topic score 0.96 (one topic), other
//! topics 0. Every name and text here is made up.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{Method, StatusCode};
use brain_module::Brain;
use brain_module::semantic::Embedder;
use serde_json::{Value, json};

use super::common::*;

const DIM: usize = 512;

#[derive(Default)]
struct Topics {
    seen: Mutex<Vec<String>>,
    hold: AtomicBool,
}

fn num(t: &str, key: &str) -> Option<usize> {
    t.split(key).nth(1)?.split_whitespace().next()?.parse().ok()
}

impl Embedder for Topics {
    fn model_id(&self) -> &str {
        "fake-topics"
    }
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        while self.hold.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.seen.lock().unwrap().extend(texts.iter().cloned());
        let a = 20f32.to_radians();
        Ok(texts
            .iter()
            .map(|t| {
                let mut v = vec![0.0; DIM];
                match (num(t, "topic="), num(t, "var=")) {
                    (Some(k), Some(var)) => {
                        v[k] = a.cos();
                        v[32 + var] = a.sin();
                    }
                    _ => v[DIM - 1] = 1.0,
                }
                v
            })
            .collect())
    }
}

/// Item `n` in folder `hint` ("" for Unsorted) about topic `k`, variant `var`.
fn it(n: u32, hint: &str, k: usize, var: usize) -> Value {
    item(
        n,
        hint,
        &format!("note {n}"),
        &format!("text {n} topic={k} var={var} "),
    )
}

fn id(n: u32) -> String {
    format!("01JD{n:022}")
}

async fn semantic(fx: &Fx, run: &str) -> Value {
    ok(fx, Method::GET, &format!("/imports/{run}/semantic"), None).await
}

async fn ready(fx: &Fx, run: &str) -> Value {
    for _ in 0..600 {
        let v = semantic(fx, run).await;
        if v["state"] != "pending" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the semantic step never finished");
}

/// Rooms the Review list shows, Unsorted not counted.
async fn rooms(fx: &Fx, run: &str) -> usize {
    proposals(fx, run)
        .await
        .iter()
        .filter(|p| p["id"] != "unsorted")
        .count()
}

/// The proposal as stored: every item's room and mark and every proposal row.
async fn dump(fx: &Fx, run: &str) -> String {
    let st = staging_pool(fx, run).await;
    let items: Vec<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT item_id, proposal, mark FROM items ORDER BY item_id")
            .fetch_all(&st)
            .await
            .unwrap();
    let props: Vec<String> = sqlx::query_scalar(
        "SELECT json_array(id, name, kind_guess, kind, signals, warnings, config, state, room) FROM proposals ORDER BY id",
    )
    .fetch_all(&st)
    .await
    .unwrap();
    st.close().await;
    format!("{items:?}\n{props:?}")
}

/// Alpha and Beta (one topic, 3 items each), Gamma (4 items, one a near-copy of another), Tiny
/// (1 item of Gamma's topic), Lonely (1 item of a topic no room has), Delta (3 items) and an
/// Unsorted item of Delta's topic.
async fn sample(fx: &Fx) -> String {
    let run = start(fx).await;
    let mut items = vec![];
    items.extend((1..=3).map(|n| it(n, "/u/Dev/Alpha", 1, n as usize)));
    items.extend((4..=6).map(|n| it(n, "/u/Dev/Beta", 1, n as usize)));
    items.extend([
        it(7, "/u/Dev/Gamma", 2, 7),
        it(8, "/u/Dev/Gamma", 2, 8),
        it(9, "/u/Dev/Gamma", 2, 9),
        it(10, "/u/Dev/Gamma", 2, 9), // a near-copy of 9, newer (day 11)
        it(11, "/u/Projects/Tiny", 2, 11),
        it(12, "/u/Projects/Lonely", 5, 12),
        it(13, "", 3, 13),
    ]);
    items.extend((14..=16).map(|n| it(n, "/u/Dev/Delta", 3, n as usize)));
    // One name twice, singular and plural, about different things: merged by the name alone.
    items.extend((17..=19).map(|n| it(n, "/u/Dev/Pricing experiment", 6, n as usize)));
    items.extend((20..=22).map(|n| it(n, "/u/Dev/Pricing experiments", 7, n as usize)));
    send(fx, &run, items).await;
    run
}

#[tokio::test]
async fn the_tidy_merges_copies_and_rooms_folds_tiny_ones_and_moves_unsorted_items() {
    let fake = Arc::new(Topics::default());
    let fx = fx_with(Brain::with_embedder(fake.clone()), 1).await;
    let run = sample(&fx).await;
    finish(&fx, &run).await;
    let v = ready(&fx, &run).await;
    let t = &v["ai_tidy"];
    assert_eq!(t["state"], "applied", "{v}");
    assert_eq!(
        t["summary"],
        json!({"duplicates_merged": 1, "rooms_merged": 2, "rooms_folded": 2, "items_moved": 1,
               "rooms_before": 8, "rooms_after": 4})
    );
    assert_eq!(
        t["changes_url"],
        format!("/modules/brain/v1/imports/{run}/semantic/changes")
    );
    // What the Review list shows: four rooms where there were eight, and no "Merge?" question.
    let p = proposals(&fx, &run).await;
    assert_eq!(rooms(&fx, &run).await, 4);
    assert!(p.iter().all(|c| c["suggest_merge"].is_null()), "{p:?}");
    let pricing: i64 = p
        .iter()
        .filter(|c| c["name"].as_str().unwrap().starts_with("Pricing"))
        .map(|c| c["item_count"].as_i64().unwrap())
        .sum();
    assert_eq!(pricing, 6);
    assert_eq!(
        by_name(&p, "Delta")["item_count"],
        4,
        "with the Unsorted item"
    );
    let gamma = by_name(&p, "Gamma");
    assert_eq!(
        gamma["item_count"], 5,
        "Gamma, its kept copy and Tiny's item"
    );
    let ab: i64 = ["Alpha", "Beta"]
        .iter()
        .filter_map(|n| p.iter().find(|x| x["name"] == *n))
        .map(|x| x["item_count"].as_i64().unwrap())
        .sum();
    assert_eq!(ab, 6, "Alpha and Beta are one room");
    // The applied suggestions are no longer offered as decisions.
    assert_eq!(v["duplicates"], json!([]));
    assert_eq!(v["merges"], json!([]));
    assert_eq!(v["closest"], json!([]));

    // See changes: each change with its items, rooms and score.
    let c = ok(
        &fx,
        Method::GET,
        &format!("/imports/{run}/semantic/changes"),
        None,
    )
    .await;
    let ch = c["changes"].as_array().unwrap();
    let kinds: Vec<&str> = ch.iter().map(|x| x["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["duplicate", "merge", "merge", "fold", "fold", "move"]
    );
    assert_eq!(ch[2]["score"], 1.0, "a merge by name");
    // Titles come with each change; a near-copy names the kept item and its room.
    assert_eq!(ch[0]["item_titles"], json!(["note 9"]));
    assert_eq!(
        (ch[0]["to_title"].as_str(), ch[0]["to_name"].as_str()),
        (Some("note 10"), Some("Gamma"))
    );
    assert_eq!(ch[5]["item_titles"], json!(["note 13"]));
    assert_eq!(
        (ch[0]["to"].as_str(), &ch[0]["item_ids"]),
        (Some(id(10).as_str()), &json!([id(9)]))
    );
    assert!(ch[0]["score"].as_f64().unwrap() > 0.99);
    let fold_to: BTreeMap<String, String> = ch
        .iter()
        .filter(|x| x["kind"] == "fold")
        .map(|x| {
            (
                x["from_name"].as_str().unwrap().to_owned(),
                x["to_name"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(fold_to["Tiny"], "Gamma");
    assert_eq!(fold_to["Lonely"], "Unsorted");
    assert_eq!(ch[5]["item_ids"], json!([id(13)]));
    assert_eq!(c["ai_tidy"]["summary"]["rooms_after"], 4);
    // Nothing reached the Brain: no room, nothing committed.
    let made: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(made, 0);
}

#[tokio::test]
async fn undo_restores_the_proposal_exactly_and_a_re_sort_tidies_again() {
    let fake = Arc::new(Topics::default());
    fake.hold.store(true, Ordering::SeqCst);
    let fx = fx_with(Brain::with_embedder(fake.clone()), 1).await;
    let run = sample(&fx).await;
    finish(&fx, &run).await;
    assert!(
        semantic(&fx, &run).await.get("ai_tidy").is_none(),
        "pending: no tidy yet"
    );
    let before = dump(&fx, &run).await;
    let n_before = rooms(&fx, &run).await;
    fake.hold.store(false, Ordering::SeqCst);
    ready(&fx, &run).await;
    assert_ne!(dump(&fx, &run).await, before);
    assert!(rooms(&fx, &run).await < n_before);

    let v = ok(
        &fx,
        Method::POST,
        &format!("/imports/{run}/semantic/undo"),
        None,
    )
    .await;
    assert_eq!(v["ai_tidy"]["state"], "undone");
    assert_eq!(dump(&fx, &run).await, before, "byte for byte");
    assert_eq!(rooms(&fx, &run).await, n_before);
    // Nothing left to undo.
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/imports/{run}/semantic/undo"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Re-sort: grouping and the local model again, and the tidy is applied again.
    ok(&fx, Method::POST, &format!("/imports/{run}/regroup"), None).await;
    let v = ready(&fx, &run).await;
    assert_eq!(v["ai_tidy"]["state"], "applied");
    assert_eq!(v["ai_tidy"]["summary"]["rooms_after"], 4);
    assert_eq!(v["ai_tidy"]["summary"]["duplicates_merged"], 1);
    // A second re-sort over an applied tidy: its near-copy is an item again first, so it is found again.
    ok(&fx, Method::POST, &format!("/imports/{run}/regroup"), None).await;
    let v = ready(&fx, &run).await;
    assert_eq!(v["ai_tidy"]["summary"]["duplicates_merged"], 1);
    assert_eq!(rooms(&fx, &run).await, 4);
}

#[tokio::test]
async fn a_committed_room_is_never_read_or_filled_by_the_tidy() {
    let fake = Arc::new(Topics::default());
    let fx = fx_with(Brain::with_embedder(fake.clone()), 1).await;
    let hidden = committed_room_named(&fx, "Hidden", &[("Secret", "hidden topic=5 var=40 ")]).await;
    // Its own import embedded it; from here on nothing may read it.
    fake.seen.lock().unwrap().clear();
    let run = sample(&fx).await;
    finish(&fx, &run).await;
    let v = ready(&fx, &run).await;
    assert_eq!(v["ai_tidy"]["state"], "applied");
    let c = ok(
        &fx,
        Method::GET,
        &format!("/imports/{run}/semantic/changes"),
        None,
    )
    .await;
    assert!(
        !c.to_string().contains(&hidden),
        "no change touches the committed room"
    );
    assert!(
        !fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.contains("hidden")),
        "its text is never read by the tidy run"
    );
}

#[tokio::test]
async fn thirty_five_rooms_with_near_copies_come_out_fewer() {
    let fake = Arc::new(Topics::default());
    let fx = fx_with(Brain::with_embedder(fake.clone()), 1).await;
    let run = start(&fx).await;
    // 35 folders over 13 topics: most topics are split across two to four folders, and every
    // fourth item is a near-copy of the one before.
    let names = [
        "Billing",
        "Invoices",
        "Payments",
        "Garden",
        "Seeds",
        "Recipes",
        "Baking",
        "Soups",
        "Sauces",
        "Travel",
        "Flights",
        "Fitness",
        "Running",
        "Reading",
        "Novels",
        "Poetry",
        "Taxes",
        "Receipts",
        "Music",
        "Guitar",
        "Lessons",
        "Kitchen",
        "Renovation",
        "Photos",
        "Prints",
        "Albums",
        "Bikes",
        "Repairs",
        "Chess",
        "Openings",
        "Puzzles",
        "Tournaments",
        "Letters",
        "Postcards",
        "Notebook",
    ];
    let topic = |r: usize| match r {
        0..=2 => 0,
        3..=4 => 1,
        5..=8 => 2,
        9..=10 => 3,
        11..=12 => 4,
        13..=15 => 6,
        16..=17 => 7,
        18..=20 => 8,
        21..=22 => 9,
        23..=25 => 10,
        26..=27 => 11,
        28..=31 => 12,
        _ => 13,
    };
    let mut items = vec![];
    let mut n = 0u32;
    for (r, name) in names.iter().enumerate() {
        for _ in 0..3 {
            n += 1;
            // The variant repeats for the copy: same topic and variant, a different text.
            let var = if n.is_multiple_of(4) {
                (n - 1) % 400
            } else {
                n % 400
            } as usize;
            items.push(it(n, &format!("/u/Dev/{name}"), topic(r), var));
        }
    }
    send(&fx, &run, items).await;
    finish(&fx, &run).await;
    let v = ready(&fx, &run).await;
    let s = &v["ai_tidy"]["summary"];
    let after = rooms(&fx, &run).await;
    println!("35-room import: {s}, Review shows {after} rooms");
    assert_eq!(s["rooms_before"], 35);
    assert!(after < 35, "{s}");
    assert_eq!(s["rooms_after"].as_u64().unwrap() as usize, after);
    assert!(s["duplicates_merged"].as_u64().unwrap() > 0);
    assert!(v["duplicates"].as_array().unwrap().is_empty());
}
