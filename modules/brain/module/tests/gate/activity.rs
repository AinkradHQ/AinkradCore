//! E9-2: the Brain's one status call (top-bar icon). Counts only; a waiting distil names its need.

use axum::http::Method;

use super::common::*;

#[tokio::test]
async fn a_distil_waiting_for_an_ai_account_is_the_one_thing_brain_needs() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("Billing", "we export invoices as CSV")]).await;
    let v = ok(&fx, Method::GET, "/activity", None).await;
    assert_eq!(v["state"], "idle", "{v}");
    assert_eq!(v["needs"].as_array().unwrap().len(), 0, "{v}");
    // No chain bound: the distil waits and the icon asks for an AI account.
    call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/distil"),
        None,
    )
    .await;
    let v = ok(&fx, Method::GET, "/activity", None).await;
    assert_eq!(v["state"], "needs_you", "{v}");
    assert_eq!(v["needs"][0]["kind"], "ai_account", "{v}");
    assert_eq!(v["needs"][0]["rooms"], 1, "{v}");
}
