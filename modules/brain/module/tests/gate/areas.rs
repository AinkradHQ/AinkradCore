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
    assert!(!matches!(kind.as_str(), "personal" | "global-safe"), "{kind}");
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
    assert_eq!((n("rules"), n("knowledge"), n("timeline"), n("me")), (1, 1, 1, 0), "{v}");
    assert_eq!(v["locked_rooms"], 0, "{v}");
    assert_eq!(v["places"], 1, "{v}");
    let v = ok(&fx, Method::GET, "/areas/knowledge", None).await;
    assert_eq!(v["records"][0]["id"], "r2", "{v}");
    assert_eq!(v["total"], 1, "{v}");
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
    let u = ok(&fx, Method::POST, &format!("/auto-imports/{run}/undo"), None).await;
    assert_eq!(u["rooms"], l[0]["rooms"], "{u}");
    let l = ok(&fx, Method::GET, "/auto-imports", None).await;
    assert_eq!(l.as_array().unwrap().len(), 0, "{l}");
    let (st, _) = call(&fx, &fx.admin, Method::POST, "/auto-imports/nope/undo", None).await;
    assert_eq!(st.as_u16(), 409);
}
