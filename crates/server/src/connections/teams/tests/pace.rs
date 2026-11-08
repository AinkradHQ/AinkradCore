//! The pacing state is per Teams instance (one per server), not global.

use serde_json::json;

use super::*;
use crate::connections::teams::{CallError, Limit};

#[tokio::test]
async fn cooling_belongs_to_one_instance() {
    let f = fx(true).await;
    let g = fx(true).await;
    let (c, d) = (f.signed_in().await, g.signed_in().await);
    f.fake.reply("post", Reply::graph(429, "TooManyRequests"));
    let a = json!({"team": TEAM_A, "channel": CH_A1, "text": "x"});
    let e = run(&f, &c, &Limit::any(), "teams.post_message", a.clone())
        .await
        .unwrap_err();
    assert!(matches!(e, CallError::Cooling { .. }));
    // Another instance (and its own connection ids) is untouched.
    run(&g, &d, &Limit::any(), "teams.post_message", a)
        .await
        .unwrap();
}
