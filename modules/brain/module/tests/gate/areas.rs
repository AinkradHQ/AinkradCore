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
