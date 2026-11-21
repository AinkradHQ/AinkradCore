//! E9-3: the areas are a lens over the records of the open rooms. Synthetic data only.

use axum::http::Method;

use super::ai::{open_room, put_record};
use super::common::*;

#[tokio::test]
async fn records_land_in_one_area_each_and_a_closed_room_is_counted_not_read() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("Billing", "we export invoices as CSV")]).await;
    let kind: String = sqlx::query_scalar("SELECT kind FROM brain_rooms WHERE id = ?")
        .bind(&room)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert!(
        !matches!(kind.as_str(), "personal" | "global-safe"),
        "{kind}"
    );
    // Not open yet: nothing is read, one room is counted as locked.
    let v = ok(&fx, Method::GET, "/areas", None).await;
    assert_eq!(v["locked_rooms"], 1, "{v}");
    open_room(&fx, &room).await;
    put_record(&fx, &room, "r1", "rule", "accepted", "ask before deleting").await;
    put_record(&fx, &room, "r2", "fact", "accepted", "Atlas syncs locally").await;
    put_record(&fx, &room, "r3", "task", "accepted", "write the docs").await;
    put_record(&fx, &room, "r4", "fact", "candidate", "not yet accepted").await;
    let v = ok(&fx, Method::GET, "/areas", None).await;
    let n = |a: &str| {
        v["areas"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["area"] == a)
            .unwrap()["count"]
            .as_i64()
            .unwrap()
    };
    assert_eq!(
        (n("rules"), n("knowledge"), n("timeline"), n("me")),
        (1, 1, 1, 0),
        "{v}"
    );
    assert_eq!(v["locked_rooms"], 0, "{v}");
    assert_eq!(v["places"], 1, "{v}");
    let v = ok(&fx, Method::GET, "/areas/knowledge", None).await;
    assert_eq!(v["records"][0]["id"], "r2", "{v}");
    assert_eq!(v["total"], 1, "{v}");
    // Learned today (the records carry a fixed 2026-11-10 date, so only a fresh one shows), and per-record archive.
    let l = ok(&fx, Method::GET, "/learned", None).await;
    assert!(l.as_array().is_some(), "{l}");
    let a = ok(
        &fx,
        Method::POST,
        &format!("/rooms/{room}/records/r1/archive"),
        None,
    )
    .await;
    assert_eq!(a["archived"], true, "{a}");
    let a = ok(
        &fx,
        Method::POST,
        &format!("/rooms/{room}/records/r1/archive"),
        None,
    )
    .await;
    assert_eq!(a["archived"], false, "{a}");
    let v = ok(&fx, Method::GET, "/areas", None).await;
    let rules = v["areas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["area"] == "rules")
        .unwrap();
    assert_eq!(rules["count"], 0, "{v}");
    // Restore is the Undo of the archive.
    let u = ok(
        &fx,
        Method::POST,
        &format!("/rooms/{room}/records/r1/restore"),
        None,
    )
    .await;
    assert_eq!(u["restored"], true, "{u}");
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/rooms/{room}/sources/nope/trace"),
        None,
    )
    .await;
    assert_eq!(st.as_u16(), 404);
    let (st, _) = call(&fx, &fx.admin, Method::GET, "/areas/places", None).await;
    assert_eq!(st.as_u16(), 404);
}

/// A run as the person imports it: every room accepted, then committed through the review routes.
async fn import_by_hand(fx: &Fx, run: &str) -> Vec<String> {
    for p in proposals(fx, run).await {
        if p["id"] != "unsorted" && p["state"] == "proposed" {
            ok(
                fx,
                Method::PATCH,
                &format!("/imports/{run}/proposals/{}", p["id"].as_str().unwrap()),
                Some(serde_json::json!({"state": "accepted"})),
            )
            .await;
        }
    }
    let c = ok(fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
    c["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["room"].as_str().unwrap().to_owned())
        .collect()
}

/// Review before filing (2026-11-21): the Core prepares a run in review and never imports it by itself.
#[tokio::test]
async fn the_core_prepares_an_import_but_files_nothing_by_itself() {
    let fx = fx().await;
    let run = start(&fx).await;
    // Without a local model, a run of 205 items: two repos of one product, and a folder too small
    // to be a place.
    let mut items: Vec<_> = (0..190)
        .map(|i| {
            item(
                i + 1,
                "/h/Projects/Kestrel/a",
                "Note",
                &format!("kestrel text {i}"),
            )
        })
        .collect();
    items.extend((190..202).map(|i| {
        item(
            i + 1,
            "/h/Projects/KestrelBackend/a",
            "Note",
            &format!("backend text {i}"),
        )
    }));
    items.extend(
        (202..205).map(|i| item(i + 1, "/h/Projects/Kites/a", "Note", &format!("kite {i}"))),
    );
    send(&fx, &run, items).await;
    assert_eq!(finish(&fx, &run).await["state"], "review");
    assert!(fx.brain.auto_import_step().await.unwrap() > 0);
    for _ in 0..3 {
        fx.brain.auto_import_step().await.unwrap();
    }
    let r = ok(&fx, Method::GET, &format!("/imports/{run}"), None).await;
    assert_eq!(r["state"], "review", "nothing is filed: {r}");
    let rooms: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(rooms, 0);
    let p: Vec<_> = proposals(&fx, &run)
        .await
        .into_iter()
        .filter(|p| p["state"] != "merged")
        .collect();
    let names: Vec<(&str, i64)> = p
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap(),
                c["item_count"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(names, [("Kestrel", 202), ("Unsorted", 3)], "{p:?}");
    assert!(p.iter().all(|c| c["state"] == "proposed"), "{p:?}");
    // One summary line for the App, and the tidy is undone like the local model's.
    let v = ok(&fx, Method::GET, &format!("/imports/{run}/semantic"), None).await;
    assert_eq!(v["state"], "off", "{v}");
    assert_eq!(v["ai_tidy"]["state"], "applied", "{v}");
    assert_eq!(v["ai_tidy"]["summary"]["rooms_merged"], 1, "{v}");
    assert_eq!(v["ai_tidy"]["summary"]["rooms_folded"], 1, "{v}");
    assert_eq!(v["ai_tidy"]["summary"]["rooms_to_unsorted"], 1, "{v}");
    assert_eq!(v["ai_tidy"]["summary"]["rooms_after"], 1, "{v}");
    ok(
        &fx,
        Method::POST,
        &format!("/imports/{run}/semantic/undo"),
        None,
    )
    .await;
    assert_eq!(
        fx.brain.auto_import_step().await.unwrap(),
        0,
        "an undone tidy is not redone"
    );
    let n = proposals(&fx, &run)
        .await
        .iter()
        .filter(|p| p["state"] != "merged" && p["id"] != "unsorted")
        .count();
    assert_eq!(n, 3);
    // The person imports it.
    assert_eq!(import_by_hand(&fx, &run).await.len(), 3);
    let l = ok(&fx, Method::GET, "/auto-imports", None).await;
    assert_eq!(l.as_array().unwrap().len(), 0, "{l}");
}

/// The App finds a run in review again, moves a whole place to Unsorted in one call, and the
/// emptied place is dropped at commit: never refused, no refusal rule drafted from it.
#[tokio::test]
async fn an_emptied_place_is_dropped_silently_at_commit() {
    let fx = fx().await;
    let run = start(&fx).await;
    let mut items: Vec<_> = (0..3)
        .map(|i| {
            item(
                i + 1,
                "/h/Projects/Kestrel/a",
                "Note",
                &format!("kestrel {i}"),
            )
        })
        .collect();
    items.extend((3..5).map(|i| {
        item(
            i + 1,
            "/h/Projects/Bramble/a",
            "Note",
            &format!("bramble {i}"),
        )
    }));
    send(&fx, &run, items).await;
    finish(&fx, &run).await;
    let l = ok(&fx, Method::GET, "/imports?state=review", None).await;
    assert_eq!(l.as_array().unwrap().len(), 1, "{l}");
    assert_eq!(
        (l[0]["run"].as_str(), l[0]["places"].as_i64()),
        (Some(run.as_str()), Some(2)),
        "{l}"
    );
    let p = proposals(&fx, &run).await;
    let id = |n: &str| by_name(&p, n)["id"].as_str().unwrap().to_owned();
    let (kestrel, bramble) = (id("Kestrel"), id("Bramble"));
    let m = ok(
        &fx,
        Method::POST,
        &format!("/imports/{run}/proposals/{bramble}/to-unsorted"),
        None,
    )
    .await;
    assert_eq!(m["items"], 2, "{m}");
    let l = ok(&fx, Method::GET, "/imports?state=review", None).await;
    assert_eq!(
        (l[0]["places"].as_i64(), l[0]["unsorted"].as_i64()),
        (Some(1), Some(2)),
        "{l}"
    );
    let rules = |fx: &Fx| {
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM brain_rules")
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    let before = rules(&fx).await;
    ok(
        &fx,
        Method::POST,
        &format!("/imports/{run}/commit"),
        Some(serde_json::json!({"keep": [kestrel]})),
    )
    .await;
    assert_eq!(
        rules(&fx).await,
        before,
        "no refusal rule from an emptied place"
    );
    let p = proposals(&fx, &run).await;
    assert_eq!(by_name(&p, "Bramble")["state"], "proposed", "{p:?}");
    let l = ok(&fx, Method::GET, "/imports?state=review", None).await;
    assert!(
        l.as_array()
            .unwrap()
            .iter()
            .all(|r| r["run"] != run.as_str()),
        "the run is closed: {l}"
    );
}

/// Runs the Core accepted by itself before 0.10.2 keep their Undo: it archives their rooms.
#[tokio::test]
async fn an_earlier_auto_import_can_still_be_undone() {
    let fx = fx().await;
    let run = start(&fx).await;
    let items = (0..3)
        .map(|i| item(i + 1, "/h/Projects/Auto/a", "Note", "auto room text"))
        .collect();
    send(&fx, &run, items).await;
    finish(&fx, &run).await;
    let rooms = import_by_hand(&fx, &run).await;
    assert!(!rooms.is_empty());
    // What 0.10.1's auto-import recorded.
    let mut c = fx.app.pool.acquire().await.unwrap();
    ainkrad_core_server::store::audit::append(
        &mut c,
        &ainkrad_core::audit::NewAuditEvent {
            actor: ainkrad_core_server::api::v1::BY,
            action: "brain.import.auto_accepted".to_owned(),
            entity: None,
            details: serde_json::json!({"run": run, "rooms": rooms}).to_string(),
        },
    )
    .await
    .unwrap();
    drop(c);
    let l = ok(&fx, Method::GET, "/auto-imports", None).await;
    assert_eq!(l[0]["run"], run, "{l}");
    let u = ok(
        &fx,
        Method::POST,
        &format!("/auto-imports/{run}/undo"),
        None,
    )
    .await;
    assert_eq!(u["rooms"], l[0]["rooms"], "{u}");
    assert!(u["items"].as_i64().unwrap() > 0, "{u}");
    let r = ok(&fx, Method::GET, &format!("/imports/{run}"), None).await;
    assert_eq!(r["state"], "review", "{r}");
    let p = proposals(&fx, &run).await;
    assert!(p.iter().all(|x| x["id"] == "unsorted"), "{p:?}");
    assert_eq!(fx.brain.auto_import_step().await.unwrap(), 0);
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/auto-imports/{run}/undo"),
        None,
    )
    .await;
    assert_eq!(st.as_u16(), 409);
    let l = ok(&fx, Method::GET, "/auto-imports", None).await;
    assert_eq!(l.as_array().unwrap().len(), 0, "{l}");
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/auto-imports/nope/undo",
        None,
    )
    .await;
    assert_eq!(st.as_u16(), 409);
}

/// The Learn step's per-place progress and cost, from the control plane.
#[tokio::test]
async fn the_learning_step_counts_places_and_sums_cost() {
    let fx = fx().await;
    let run = start(&fx).await;
    send(
        &fx,
        &run,
        vec![item(1, "/h/Projects/Lrn/a", "Note", "learn text")],
    )
    .await;
    finish(&fx, &run).await;
    assert_eq!(import_by_hand(&fx, &run).await.len(), 1);
    let v = ok(&fx, Method::GET, &format!("/imports/{run}/learning"), None).await;
    assert_eq!(v["places"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["places"][0]["state"], "pending", "{v}");
    assert_eq!(v["places"][0]["left"], 1, "{v}");
    assert_eq!(v["total_cost_usd_micros"], 0, "{v}");
    assert_eq!(v["done"], false, "{v}");
}
