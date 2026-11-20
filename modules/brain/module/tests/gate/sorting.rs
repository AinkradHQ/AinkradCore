//! Review sorting on an import shaped like a real one, through the gate: a vault that holds every
//! project's notes, AI-session transcripts that all open with the same instructions, two employer
//! rooms that are one project ("same project as"), the AI tidy's guard, and an import that never
//! stores one item twice. Every name, path and text here is made up (the two employer names are
//! the Core's own seed list).

use std::sync::Arc;
use std::time::Duration;

use axum::http::{Method, StatusCode};
use brain_model::item::hash_of;
use brain_module::Brain;
use brain_module::semantic::Embedder;
use serde_json::{Value, json};

use super::common::*;

/// A bag of words hashed into 64 buckets: texts with the same words read alike.
struct Words;
impl Embedder for Words {
    fn model_id(&self) -> &str {
        "fake-words"
    }
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        Ok(texts
            .iter()
            .map(|t| {
                let mut v = vec![0.0f32; 64];
                v[0] = 0.01;
                for w in brain_model::semantic::tokens(t) {
                    let h = w
                        .bytes()
                        .fold(7u64, |a, b| a.wrapping_mul(31).wrapping_add(b.into()));
                    v[(h % 63 + 1) as usize] += 1.0;
                }
                v
            })
            .collect())
    }
}

const WORDS: &[&str] = &[
    "lantern", "harbor", "copper", "meadow", "falcon", "quartz", "willow", "ember", "glacier",
    "orchid", "pebble", "thistle", "canyon", "saffron", "beacon", "juniper", "marble", "tundra",
    "velvet", "cobalt", "prairie", "sparrow", "granite", "nectar", "obsidian", "lagoon", "fennel",
];

/// `n` words picked by a little generator seeded with `seed`: different seeds, different texts.
fn words(seed: usize, n: usize) -> String {
    let mut x = seed as u64 * 2_654_435_761 + 1;
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            WORDS[(x >> 33) as usize % WORDS.len()]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A collected item of any kind; `hint` absent for a file (a vault note has none).
fn raw(n: u32, kind: &str, path: &str, hint: Option<&str>, title: &str, text: &str) -> Value {
    json!({
        "item_id": format!("01JE{n:022}"),
        "source_kind": kind,
        "content_hash": hash_of(text),
        "origin": {"device": "mac-1", "path": path},
        "project_hint": hint,
        "author": {"kind": "person", "name": "dev"},
        "title": title,
        "text": text,
        "links": [],
        "started_at": format!("2026-10-{:02}T09:30:00Z", 1 + n % 28),
    })
}

fn preamble() -> String {
    (0..45)
        .map(|i| {
            format!("Rule {i:02}: keep every change small, tested and reviewed by a person.\n")
        })
        .collect()
}

async fn ready(fx: &Fx, run: &str) -> Value {
    for _ in 0..1500 {
        let v = ok(fx, Method::GET, &format!("/imports/{run}/semantic"), None).await;
        if v["state"] != "pending" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the semantic step never finished");
}

async fn accept_all(fx: &Fx, run: &str) {
    for p in proposals(fx, run).await {
        if p["id"] != "unsorted" {
            ok(
                fx,
                Method::PATCH,
                &format!("/imports/{run}/proposals/{}", p["id"].as_str().unwrap()),
                Some(json!({"state": "accepted"})),
            )
            .await;
        }
    }
}

async fn commit(fx: &Fx, run: &str) -> Value {
    ok(fx, Method::POST, &format!("/imports/{run}/commit"), None).await
}

/// `(item_id, text)` of every source of every room.
async fn sources(fx: &Fx) -> Vec<(String, String, String)> {
    let rooms: Vec<String> = sqlx::query_scalar("SELECT id FROM brain_rooms ORDER BY id")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    let mut out = vec![];
    for r in rooms {
        let c = canon_pool(fx, &r).await;
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT item_id, text FROM sources ORDER BY item_id")
                .fetch_all(&c)
                .await
                .unwrap();
        c.close().await;
        out.extend(rows.into_iter().map(|(i, t)| (r.clone(), i, t)));
    }
    out
}

#[tokio::test]
async fn a_vault_of_every_project_and_one_preamble_keep_every_project_apart() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Words)), 1).await;
    let run = start(&fx).await;
    let pre = preamble();
    let first = pre.lines().next().unwrap().to_owned();
    let mut items = vec![];
    let mut n = 0;
    // 60 transcripts over three projects, each opening with the same 3 KB of instructions.
    for i in 0..60usize {
        let p = ["ProjectA", "ProjectB", "ProjectC"][i % 3];
        n += 1;
        items.push(raw(
            n,
            "claude_code",
            &format!("/u/.claude/projects/s{i}.jsonl"),
            Some(&format!("/u/Home/Projects/{p}")),
            &first,
            &format!(
                "User: {pre}\nUser: task {i}: {}\n\nAssistant: Done.",
                words(i, 16)
            ),
        ));
    }
    // The vault "Ainkrad": every project's notes under WorkShop/<project>.
    for p in ["ProjectA", "ProjectB", "ProjectC"] {
        for j in 0..5 {
            n += 1;
            items.push(raw(
                n,
                "vault",
                &format!("/u/Ainkrad/WorkShop/{p}/Notes/n{j}.md"),
                None,
                &format!("{p} note {j}"),
                &format!("# {p} note {j}\n{}", words(100 + n as usize, 30)),
            ));
        }
    }
    // One real near-copy: one note saved twice, the last word changed.
    let body = words(999, 60);
    for (k, last) in ["draft", "final"].iter().enumerate() {
        n += 1;
        items.push(raw(
            n,
            "vault",
            &format!("/u/Ainkrad/WorkShop/ProjectB/Plans/plan-{k}.md"),
            None,
            "ProjectB plan",
            &format!("# ProjectB plan\n{body} {last}"),
        ));
    }
    send(&fx, &run, items).await;
    finish(&fx, &run).await;
    let v = ready(&fx, &run).await;
    assert_eq!(v["ai_tidy"]["state"], "applied", "{v}");
    assert_eq!(v["ai_tidy"]["summary"]["duplicates_merged"], 1, "{v}");
    let p = proposals(&fx, &run).await;
    let names: Vec<&str> = p.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["ProjectA", "ProjectB", "ProjectC"], "{p:?}");
    assert_eq!(by_name(&p, "ProjectA")["item_count"], 25);
    assert_eq!(
        by_name(&p, "ProjectB")["item_count"],
        27,
        "with both copies, one merged"
    );
    assert_eq!(by_name(&p, "ProjectC")["item_count"], 25);
    let c = ok(
        &fx,
        Method::GET,
        &format!("/imports/{run}/semantic/changes"),
        None,
    )
    .await;
    let dup = &c["changes"][0];
    assert_eq!(dup["kind"], "duplicate");
    assert_eq!(dup["item_titles"], json!(["ProjectB plan"]));
}

#[tokio::test]
async fn same_project_as_merges_now_and_in_every_later_import() {
    let fx = fx().await;
    let two_rooms = |from: u32| {
        let mut v: Vec<Value> = (0..3)
            .map(|i| {
                item(
                    from + i,
                    "/u/Home/Projects/harborauto/a",
                    &format!("d{i}"),
                    &format!("dealer listing {from} {i}"),
                )
            })
            .collect();
        v.extend((3..6).map(|i| {
            item(
                from + i,
                "/u/Home/Projects/HarborMotors/b",
                &format!("a{i}"),
                &format!("dealer calls {from} {i}"),
            )
        }));
        v
    };
    let run = start(&fx).await;
    send(&fx, &run, two_rooms(1)).await;
    finish(&fx, &run).await;
    let p = proposals(&fx, &run).await;
    let (dvx, auto) = (
        by_name(&p, "harborauto")["id"].clone(),
        by_name(&p, "HarborMotors")["id"].clone(),
    );
    let card = ok(
        &fx,
        Method::POST,
        &format!(
            "/imports/{run}/proposals/{}/same-project",
            dvx.as_str().unwrap()
        ),
        Some(json!({"into": auto})),
    )
    .await;
    assert_eq!(card["name"], "HarborMotors");
    assert_eq!(card["item_count"], 6);
    assert_eq!(card["warnings"], json!([]), "one employer now, not mixed");
    // It can be accepted: the employer guard counts the two as one.
    ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{run}/proposals/{}", auto.as_str().unwrap()),
        Some(json!({"state": "accepted"})),
    )
    .await;
    let list = ok(&fx, Method::GET, "/aliases", None).await;
    assert_eq!(list, json!([{"from": "harborauto", "to": "HarborMotors"}]));
    // A re-sort keeps them one.
    ok(&fx, Method::POST, &format!("/imports/{run}/regroup"), None).await;
    let p = proposals(&fx, &run).await;
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0]["item_count"], 6);
    // A later import files them as one at once.
    let run2 = start(&fx).await;
    send(&fx, &run2, two_rooms(20)).await;
    finish(&fx, &run2).await;
    let p = proposals(&fx, &run2).await;
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(
        (p[0]["name"].as_str(), p[0]["item_count"].as_i64()),
        (Some("HarborMotors"), Some(6))
    );
    // Undone: the next re-sort keeps them apart again.
    assert_eq!(
        ok(&fx, Method::DELETE, "/aliases/harborauto", None).await,
        json!([])
    );
    ok(&fx, Method::POST, &format!("/imports/{run2}/regroup"), None).await;
    assert_eq!(proposals(&fx, &run2).await.len(), 2);
    let (s, _) = call(&fx, &fx.admin, Method::DELETE, "/aliases/harborauto", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_ai_is_not_confident_when_its_tidy_would_collapse_the_proposal() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Words)), 1).await;
    let run = start(&fx).await;
    let body = words(5, 30);
    let items: Vec<Value> = (0..40u32)
        .map(|i| {
            raw(
                i + 1,
                "vault",
                &format!("/u/Vault/WorkShop/Project{}/n{i}.md", i % 8),
                None,
                &format!("n{i}"),
                &format!("{body} {}", WORDS[i as usize % WORDS.len()]),
            )
        })
        .collect();
    send(&fx, &run, items).await;
    finish(&fx, &run).await;
    let before = proposals(&fx, &run).await;
    let v = ready(&fx, &run).await;
    assert_eq!(v["ai_tidy"]["state"], "declined", "{v}");
    assert!(
        v["ai_tidy"]["summary"]["duplicates_merged"]
            .as_u64()
            .unwrap()
            > 12
    );
    assert_eq!(
        proposals(&fx, &run).await.len(),
        before.len(),
        "nothing changed"
    );
    let c = ok(
        &fx,
        Method::GET,
        &format!("/imports/{run}/semantic/changes"),
        None,
    )
    .await;
    assert_eq!(c["changes"], json!([]));
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/imports/{run}/semantic/undo"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // The near-copies are still offered, for the person to decide.
    assert!(!v["duplicates"].as_array().unwrap().is_empty());
}

/// (a) Import pressed again while the first run waits, a re-sort in between, a resumed collect
/// and a second commit: every item is stored once.
#[tokio::test]
async fn importing_again_resuming_or_re_sorting_never_stores_an_item_twice() {
    let fx = fx().await;
    let batch: Vec<Value> = (1..=4)
        .map(|i| {
            item(
                i,
                "/u/Home/Projects/Bramble/a",
                &format!("t{i}"),
                &format!("bramble text {i}"),
            )
        })
        .collect();
    let run1 = start(&fx).await;
    let run2 = start(&fx).await;
    send(&fx, &run1, batch.clone()).await;
    // A resumed collect sends an item again, its file changed meanwhile: replaced, not added.
    let mut again = item(
        4,
        "/u/Home/Projects/Bramble/a",
        "t4",
        "bramble text 4, edited",
    );
    again["started_at"] = json!("2026-11-30T10:00:00Z");
    send(&fx, &run1, vec![again.clone()]).await;
    send(&fx, &run2, batch.clone()).await;
    finish(&fx, &run1).await;
    finish(&fx, &run2).await;
    assert_eq!(
        by_name(&proposals(&fx, &run1).await, "Bramble")["item_count"],
        4
    );
    accept_all(&fx, &run1).await;
    commit(&fx, &run1).await;
    // Run 2 holds the same items; re-sorted, then imported.
    ok(&fx, Method::POST, &format!("/imports/{run2}/regroup"), None).await;
    accept_all(&fx, &run2).await;
    let r = commit(&fx, &run2).await;
    assert_eq!(r["rooms"][0]["sources"], 0, "nothing new: {r}");
    let all = sources(&fx).await;
    let ids: std::collections::HashSet<&str> = all.iter().map(|s| s.1.as_str()).collect();
    assert_eq!((ids.len(), all.len()), (4, 4), "no item twice: {all:?}");
    // Run 2's older text of item 4 did not replace run 1's newer one.
    let four: Vec<&str> = all
        .iter()
        .filter(|s| s.1.ends_with("04"))
        .map(|s| s.2.as_str())
        .collect();
    assert_eq!(four, ["bramble text 4, edited"]);
    // The same items once more in a new run: all already known.
    let run3 = start(&fx).await;
    let mut last = batch[..3].to_vec();
    last.push(again);
    let v = send(&fx, &run3, last).await;
    assert!(
        v["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["status"] == "duplicate"),
        "{v}"
    );
}

/// (b) An item imported before and imported again with new text, even sorted into another room
/// this time, is updated in place in the room it lives in.
#[tokio::test]
async fn an_item_imported_again_with_new_text_is_updated_where_it_lives() {
    let fx = fx().await;
    let run = start(&fx).await;
    send(
        &fx,
        &run,
        (1..=3)
            .map(|i| {
                item(
                    i,
                    "/u/Home/Projects/Bramble/a",
                    &format!("t{i}"),
                    &format!("first text {i}"),
                )
            })
            .collect(),
    )
    .await;
    finish(&fx, &run).await;
    accept_all(&fx, &run).await;
    let home = commit(&fx, &run).await["rooms"][0]["room"]
        .as_str()
        .unwrap()
        .to_owned();
    let run2 = start(&fx).await;
    let mut items: Vec<Value> = (1..=3)
        .map(|i| {
            item(
                10 + i,
                "/u/Home/Projects/Kestrel/a",
                &format!("k{i}"),
                &format!("kestrel {i}"),
            )
        })
        .collect();
    // Item 1 again, edited, and this time in Kestrel's folder.
    items.push(item(
        1,
        "/u/Home/Projects/Kestrel/a",
        "t1",
        "first text 1, edited later",
    ));
    send(&fx, &run2, items).await;
    finish(&fx, &run2).await;
    accept_all(&fx, &run2).await;
    commit(&fx, &run2).await;
    let all = sources(&fx).await;
    let one: Vec<&(String, String, String)> = all
        .iter()
        .filter(|s| s.1 == format!("01JD{:022}", 1))
        .collect();
    assert_eq!(one.len(), 1, "{all:?}");
    assert_eq!(
        (one[0].0.as_str(), one[0].2.as_str()),
        (home.as_str(), "first text 1, edited later")
    );
    assert_eq!(all.len(), 6);
    let counted: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_seen WHERE room = ?")
        .bind(&home)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(counted, 3, "the room counts the updated item once");
}

/// (c) A near-copy the AI tidy merged is not imported as a record of its own.
#[tokio::test]
async fn a_near_copy_the_tidy_merged_is_not_imported() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Words)), 1).await;
    let run = start(&fx).await;
    let body = words(3, 60);
    let mut items: Vec<Value> = (1..=4)
        .map(|i| {
            raw(
                i,
                "vault",
                &format!("/u/V/WorkShop/Bramble/n{i}.md"),
                None,
                &format!("n{i}"),
                &words(40 + i as usize, 30),
            )
        })
        .collect();
    items.push(raw(
        5,
        "vault",
        "/u/V/WorkShop/Bramble/p0.md",
        None,
        "plan",
        &format!("{body} draft"),
    ));
    items.push(raw(
        6,
        "vault",
        "/u/V/WorkShop/Bramble/p1.md",
        None,
        "plan",
        &format!("{body} final"),
    ));
    send(&fx, &run, items).await;
    finish(&fx, &run).await;
    let v = ready(&fx, &run).await;
    assert_eq!(v["ai_tidy"]["summary"]["duplicates_merged"], 1, "{v}");
    accept_all(&fx, &run).await;
    commit(&fx, &run).await;
    let all = sources(&fx).await;
    assert_eq!(all.len(), 5, "{all:?}");
    assert!(all.iter().any(|s| s.2.ends_with("final")));
    assert!(
        !all.iter().any(|s| s.2.ends_with("draft")),
        "the merged copy stays out"
    );
}

/// A repo room next to its project merges into it (and shows in See changes, and undoes); a session
/// whose folder is Claude Code's dash-encoded one lands in the project, never in a room of that name.
#[tokio::test]
async fn a_repo_room_joins_its_project_and_an_encoded_folder_is_decoded() {
    let fx = fx_with(Brain::with_embedder(Arc::new(Words)), 1).await;
    let run = start(&fx).await;
    let mut items: Vec<Value> = (1..=15)
        .map(|i| {
            item(
                i,
                "/u/Home/Projects/Kestrel/a",
                &format!("k{i}"),
                &words(i as usize, 20),
            )
        })
        .collect();
    items.extend((16..=17).map(|i| {
        item(
            i,
            "/u/Home/Projects/kestrelbackend",
            &format!("b{i}"),
            &words(i as usize, 20),
        )
    }));
    items.push(item(
        18,
        "-Users-someone-Home-Projects-Kestrel",
        "enc",
        &words(18, 20),
    ));
    send(&fx, &run, items).await;
    finish(&fx, &run).await;
    let names: Vec<String> = proposals(&fx, &run)
        .await
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(!names.iter().any(|n| n.contains("Users")), "{names:?}");
    let v = ready(&fx, &run).await;
    assert_eq!(v["ai_tidy"]["summary"]["rooms_merged"], 1, "{v}");
    let p = proposals(&fx, &run).await;
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(by_name(&p, "Kestrel")["item_count"], 18);
    let c = ok(
        &fx,
        Method::GET,
        &format!("/imports/{run}/semantic/changes"),
        None,
    )
    .await;
    let m = c["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["kind"] == "merge")
        .unwrap()
        .clone();
    assert_eq!(
        (m["from_name"].as_str(), m["to_name"].as_str()),
        (Some("kestrelbackend"), Some("Kestrel"))
    );
    ok(
        &fx,
        Method::POST,
        &format!("/imports/{run}/semantic/undo"),
        None,
    )
    .await;
    assert_eq!(
        proposals(&fx, &run).await.len(),
        2,
        "undone: the repo room is back"
    );
}
