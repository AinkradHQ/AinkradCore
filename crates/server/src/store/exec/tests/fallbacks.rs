//! Fallback chains at dispatch and on the run (E15.3): a run starts on the first entry with
//! an account its company may use, records why; a runner's fallback moves it along the chain
//! and nowhere else, once, and cools off an account that was refused.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::{AccountId, AccountStatus, Billing};
use ainkrad_core::org::ModelRoute;

use super::wake::{runner, wake};
use super::*;
use crate::store::gov::{
    assign_account, create_account, get_account, new_account, set_account_status, set_billing,
};
use crate::store::org::{list_fallbacks, set_fallbacks};

const BY: AuditActor = AuditActor::User(UserId(1));
const NOW: &str = "2026-10-22T10:00:00.000Z";

fn route(harness: Harness, model: &str) -> ModelRoute {
    ModelRoute {
        harness,
        model: model.to_owned(),
    }
}

async fn account(pool: &SqlitePool, harness: Harness, label: &str, company: CompanyId) -> i64 {
    let new = new_account(
        pool,
        harness,
        label,
        None,
        None,
        None,
        Some(Billing::Metered),
    );
    let a = create_account(pool, &new.await.unwrap(), BY).await.unwrap();
    assign_account(pool, a.id, company, true, BY).await.unwrap();
    a.id.0
}

#[tokio::test]
async fn a_run_starts_on_the_first_entry_with_an_account_and_says_why() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = crate::store::org::get_agent(pool, dev)
        .await
        .unwrap()
        .unwrap()
        .company_id;
    let chain = [
        route(Harness::Claude, "claude-sonnet"),
        route(Harness::Codex, "gpt-x"),
    ];
    assert!(set_fallbacks(pool, dev, &chain, BY).await.unwrap());
    assert_eq!(list_fallbacks(pool, dev).await.unwrap(), chain);
    for bad in [
        vec![route(Harness::Claude, "claude-opus")],
        vec![route(Harness::Codex, "x"), route(Harness::Codex, "x")],
        vec![route(Harness::Codex, " ")],
    ] {
        let e = set_fallbacks(pool, dev, &bad, BY).await.unwrap_err();
        assert!(matches!(e, Error::InvalidArgument(_)), "{bad:?}");
    }
    // Claude has a pool, and A's only Claude account is off; Codex has no pool.
    let off = account(pool, Harness::Claude, "claude-a", company).await;
    set_account_status(pool, AccountId(off), AccountStatus::Disabled, None, BY)
        .await
        .unwrap();
    let r = runner(pool, "box").await;
    enqueue_wake(pool, &wake(dev, Some(i), "w")).await.unwrap();
    // A runner without Codex has nothing it can start.
    let claude_only = dispatch_next(pool, r, &[], &[Harness::Claude], NOW).await;
    assert!(claude_only.unwrap().is_none());
    let run = dispatch_next(pool, r, &[], &Harness::ALL, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.harness, Harness::Codex);
    assert_eq!(run.model_used.as_deref(), Some("gpt-x"));
    assert_eq!(run.account_id, None, "no Codex pool: the runner's login");
    assert_eq!(
        run.fallback_reason.as_deref(),
        Some(
            "claude/claude-opus: no_account: no active account; \
             claude/claude-sonnet: no_account: no active account"
        )
    );
}

#[tokio::test]
async fn a_fallback_moves_the_run_along_its_chain_only_once() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = crate::store::org::get_agent(pool, dev)
        .await
        .unwrap()
        .unwrap()
        .company_id;
    let first = account(pool, Harness::Claude, "claude-1", company).await;
    let second = account(pool, Harness::Claude, "claude-2", company).await;
    let other = create_company(pool, "B").await.unwrap().id;
    let theirs = account(pool, Harness::Claude, "claude-b", other).await;
    set_fallbacks(pool, dev, &[route(Harness::Claude, "claude-haiku")], BY)
        .await
        .unwrap();
    set_billing(pool, Harness::Claude, Billing::Metered, BY)
        .await
        .unwrap();
    let r = runner(pool, "box").await;
    enqueue_wake(pool, &wake(dev, Some(i), "w")).await.unwrap();
    let run = dispatch_next(pool, r, &[], &Harness::ALL, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.account_id.map(|a| a.0), Some(first));
    assert_eq!(run.fallback_reason, None);
    let offered = fallback_routes(pool, &run, &Harness::ALL, NOW)
        .await
        .unwrap();
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].0, route(Harness::Claude, "claude-haiku"));
    assert_eq!(offered[0].1.as_ref().map(|a| a.id.0), Some(second));

    let by = AuditActor::Runner(r);
    let haiku = route(Harness::Claude, "claude-haiku");
    let outside = route(Harness::Codex, "gpt-x");
    fn to(r: &ModelRoute, a: i64) -> Fallback<'_> {
        Fallback {
            to: r,
            account: Some(AccountId(a)),
            class: "rate_limited",
            reason: "API Error: 429",
        }
    }
    let e = switch_route(pool, run.id, &to(&outside, second), by, NOW).await;
    assert!(
        matches!(e, Err(SwitchError::Refused(_))),
        "not in the chain"
    );
    let e = switch_route(pool, run.id, &to(&haiku, theirs), by, NOW).await;
    assert!(
        matches!(e, Err(SwitchError::Refused(_))),
        "another company's account: {e:?}"
    );
    let moved = switch_route(pool, run.id, &to(&haiku, second), by, NOW)
        .await
        .unwrap();
    assert_eq!(moved.model_used.as_deref(), Some("claude-haiku"));
    assert_eq!(moved.account_id.map(|a| a.0), Some(second));
    assert_eq!(
        moved.fallback_reason.as_deref(),
        Some("claude/claude-opus: rate_limited: API Error: 429")
    );
    // A resend changes nothing.
    let again = switch_route(pool, run.id, &to(&haiku, second), by, NOW)
        .await
        .unwrap();
    assert_eq!(again, moved);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'run.fallback'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(n, 1);
    // The refused account cools off; the new one counts the prompt.
    let cooled = get_account(pool, AccountId(first)).await.unwrap().unwrap();
    assert_eq!(cooled.status, AccountStatus::Limited);
    assert_eq!(
        cooled.status_until.as_deref(),
        Some("2026-10-22T10:15:00.000Z")
    );
    let messages: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_events WHERE account_id = ? AND kind = 'message'",
    )
    .bind(second)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(messages, 1);
}
