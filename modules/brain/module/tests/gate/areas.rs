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

/// E9-5: a full run in review is accepted and imported by the Core; Undo archives its rooms.
#[tokio::test]
async fn the_core_accepts_a_sorted_import_by_itself_and_undo_archives_its_rooms() {
    let fx = fx().await;
    let run = start(&fx).await;
    let items = (0..3)
        .map(|i| item(i + 1, "/h/Projects/Auto/a", "Note", "auto room text"))
        .collect();
    send(&fx, &run, items).await;
    let v = finish(&fx, &run).await;
    assert_eq!(v["state"], "review", "{v}");
    // The semantic step may still be pending: the step waits, so poll until it has made the room.
    let mut made = 0;
    for _ in 0..600 {
        made = fx.brain.auto_import_step().await.unwrap();
        if made > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(made > 0);
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
    // Back to one pile: the run is open for review again, everything in Unsorted, and the Core
    // does not accept it again by itself.
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
    let mut made = 0;
    for _ in 0..600 {
        made = fx.brain.auto_import_step().await.unwrap();
        if made > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(made > 0);
    let v = ok(&fx, Method::GET, &format!("/imports/{run}/learning"), None).await;
    assert_eq!(v["places"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["places"][0]["state"], "pending", "{v}");
    assert_eq!(v["total_cost_usd_micros"], 0, "{v}");
    assert_eq!(v["done"], false, "{v}");
}
