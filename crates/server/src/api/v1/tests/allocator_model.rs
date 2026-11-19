//! E7 closeout: the allocator skips an account that switched the requested model off, even in a pool
//! that other accounts share, and refuses (never waits) when no ready account allows it.

use super::allocator::{took, w};
use super::chains::BY;
use super::*;
use crate::store::account_models;
use crate::store::alloc::Outcome;

const MODEL: &str = "claude-opus-5-5";

#[tokio::test]
async fn a_switched_off_model_skips_that_account_in_a_shared_pool_and_refuses_when_none_allows_it()
{
    let w = w().await;
    let (a, b) = (w.acct("a").await.id, w.acct("b").await.id);
    let mut e = w.keys("main", &[a, b]).await;
    e.model = Some(MODEL.to_owned());
    let chain = [e];
    let (p, by) = (&w.fx.app.pool, &w.fx.dev.id);
    // Seat order would give account a; it has the model off, so b takes it.
    account_models::set_allowed(p, a, MODEL, false, by, BY, NOW)
        .await
        .unwrap();
    let s = w.session(&chain, &[]).await;
    assert_eq!(took(w.pick(&s.id, &chain, NOW).await).account, b);
    // Both off: a refusal that names the reason, not a wait.
    account_models::set_allowed(p, b, MODEL, false, by, BY, NOW)
        .await
        .unwrap();
    let s = w.session(&chain, &[]).await;
    match w.pick(&s.id, &chain, NOW).await {
        Outcome::Exhausted(why) => assert!(why[0].1.contains("model switched off"), "{why:?}"),
        o => panic!("not refused: {o:?}"),
    }
}
