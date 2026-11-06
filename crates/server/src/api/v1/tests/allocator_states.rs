//! The allocator and account state (KAN-437 S4): no disabled, cooling, limited or unhealthy
//! account is ever picked (an unhealthy one with no end too), a pending auth signal keeps an
//! account out, a pool or an account with no budget room is skipped, and a pick waits only for a
//! window that ends within `wait_max`. The clock is the test's.

use ainkrad_proto::v2::{PlanLimit, PlanWindow, UpstreamStatus};

use super::allocator::{P, W, p, took, w};
use super::health::at;
use super::*;
use crate::scheduler::unix_secs;
use crate::store::agents::SessionSecret;
use crate::store::alloc::{Outcome, WAIT_MAX_SECS};
use crate::store::budgets::{self, NewBudget};
use crate::store::health::{self, Signal};
use crate::store::{accounts as acc, begin_write};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

fn exhausted(o: Outcome) -> Vec<(usize, String)> {
    match o {
        Outcome::Exhausted(r) => r,
        other => panic!("not exhausted: {other:?}"),
    }
}

async fn set_state(w: &W, id: i64, state: &str, until: Option<&str>) {
    let by = &w.fx.dev.id;
    acc::set_state(&w.fx.app.pool, id, state, None, until, by, BY, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn no_unavailable_account_is_picked_and_only_a_timed_window_is_worth_waiting_for() {
    let w = w().await;
    let healthy = w.acct("healthy").await;
    let mut out = Vec::new();
    for (label, how) in ["disabled", "manual", "limited", "cooling", "flaky"]
        .into_iter()
        .enumerate()
    {
        let a = w.acct(&format!("{how}-{label}")).await;
        match how {
            "disabled" => set_state(&w, a.id, "disabled", None).await,
            // An admin's own state, even with an end, stays until the admin changes it.
            "manual" => set_state(&w, a.id, "cooling", Some(&at(60))).await,
            "limited" => w.signal(a.id, UpstreamStatus::Quota, None, &at(0)).await,
            "cooling" => {
                w.signal(a.id, UpstreamStatus::RateLimited, Some(120), &at(0))
                    .await
            }
            _ => {
                for i in 0..3 {
                    w.signal(a.id, UpstreamStatus::ServerError, None, &at(i))
                        .await;
                }
            }
        }
        out.push((how, a.id));
    }
    for (how, id) in &out {
        let chain = [w.keys(&format!("only-{how}"), &[*id]).await];
        let s = w.session(&chain, &[]).await;
        let got = w.pick(&s.id, &chain, &at(5)).await;
        match *how {
            // A window of ten minutes or two minutes ends within the wait.
            "cooling" => assert!(
                matches!(got, Outcome::Wait { until, .. } if until == unix_secs(&at(120)).unwrap())
            ),
            "flaky" => assert!(matches!(got, Outcome::Wait { .. }), "{got:?}"),
            // Six hours is too long; the others never end by themselves.
            _ => {
                exhausted(got);
            }
        }
    }
    // Beside a healthy account none of them is ever chosen.
    let mut ids: Vec<i64> = out.iter().map(|(_, id)| *id).collect();
    ids.push(healthy.id);
    let chain = [w.keys("all", &ids).await];
    for _ in 0..3 {
        let s = w.session(&chain, &[]).await;
        assert_eq!(
            took(w.pick(&s.id, &chain, &at(5)).await).account,
            healthy.id
        );
    }
}

#[tokio::test]
async fn a_subscription_suspected_of_a_dead_login_stays_out_with_no_end_to_wait_for() {
    let w = w().await;
    let plan = w.sub("plan").await;
    for i in 0..3 {
        let mut tx = begin_write(&w.fx.app.pool).await.unwrap();
        let sig = Signal::HarnessEnd { class: "auth" };
        health::on_signal(&mut tx, plan.id, "as_x", sig, &at(i))
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let a = acc::get(&w.fx.app.pool, plan.id).await.unwrap();
    assert_eq!(
        (a.state.as_str(), a.state_reason.as_deref(), a.state_until),
        ("unhealthy", Some("auth_suspected"), None)
    );
    let chain = [w.pool("plan", "claude-sub", &[plan.id]).await];
    let s = w.session(&chain, &[]).await;
    exhausted(w.pick(&s.id, &chain, &at(10)).await);
    // A week later it is still out: nothing recovers it but the admin.
    exhausted(w.pick(&s.id, &chain, &at(7 * 86_400)).await);
}

#[tokio::test]
async fn a_plan_limit_snapshot_keeps_the_subscription_out_until_the_window_resets() {
    let w = w().await;
    let plan = w.sub("plan").await;
    let chain = [w.pool("plan", "claude-sub", &[plan.id]).await];
    let named = SessionSecret {
        name: plan.secret_name.clone(),
        var: "CLAUDE_CODE_OAUTH_TOKEN".to_owned(),
    };
    let live = w.session(&chain, &[named]).await;
    let reset = unix_secs(&at(600)).unwrap();
    let snap = PlanLimit {
        status: "allowed_warning".to_owned(),
        windows: vec![PlanWindow {
            name: "five_hour".to_owned(),
            utilization: 0.96,
            resets_at: Some(reset),
        }],
    };
    let mut tx = begin_write(&w.fx.app.pool).await.unwrap();
    health::on_signal(
        &mut tx,
        plan.id,
        &live.id,
        Signal::HarnessPlan { plan: &snap },
        &at(0),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let s = w.session(&chain, &[]).await;
    assert!(
        matches!(w.pick(&s.id, &chain, &at(1)).await, Outcome::Wait { until, .. } if until == reset)
    );
    // The window has reset: the account is back.
    assert_eq!(took(w.pick(&s.id, &chain, &at(601)).await).account, plan.id);
}

#[tokio::test]
async fn a_pending_auth_signal_keeps_an_account_out_until_it_is_decided() {
    let w = w().await;
    let a = w.acct("a").await;
    let chain = [w.keys("main", &[a.id]).await];
    let s = w.session(&chain, &[]).await;
    sqlx::query(
        "INSERT INTO core_account_auth_signals (account_id, session, gw_key, seen_at) \
         VALUES (?, 'as_old', 'gw:as_old:0:1', ?)",
    )
    .bind(a.id)
    .bind(NOW)
    .execute(&w.fx.app.pool)
    .await
    .unwrap();
    let r = exhausted(w.pick(&s.id, &chain, NOW).await);
    assert!(r[0].1.contains("auth failure"), "{r:?}");
    sqlx::query("UPDATE core_account_auth_signals SET state = 'cleared'")
        .execute(&w.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(took(w.pick(&s.id, &chain, NOW).await).account, a.id);
}

#[tokio::test]
async fn the_wait_ends_at_wait_max_to_the_second_and_is_recorded_once() {
    let w = w().await;
    let (near, far) = (w.acct("near").await, w.acct("far").await);
    let wait = u64::try_from(WAIT_MAX_SECS).unwrap();
    w.signal(near.id, UpstreamStatus::RateLimited, Some(wait), &at(0))
        .await;
    w.signal(far.id, UpstreamStatus::RateLimited, Some(wait + 1), &at(0))
        .await;
    let chain = [
        w.keys("near", &[near.id]).await,
        w.keys("far", &[far.id]).await,
    ];
    let near_only = &chain[..1];
    let far_only = &chain[1..];
    let s = w.session(near_only, &[]).await;
    let until = unix_secs(&at(WAIT_MAX_SECS)).unwrap();
    for t in [0, 5] {
        let got = w.pick(&s.id, near_only, &at(t)).await;
        assert!(
            matches!(got, Outcome::Wait { until: u, .. } if u == until),
            "{got:?}"
        );
    }
    exhausted(w.pick(&s.id, far_only, &at(0)).await);
    // Both: the earliest end decides, and nothing is picked from a cooling account.
    assert!(
        matches!(w.pick(&s.id, &chain, &at(0)).await, Outcome::Wait { until: u, .. } if u == until)
    );
    // The session row says until when, and one agent.state event was written for it.
    let (waiting, state): (String, String) =
        sqlx::query_as("SELECT waiting, state FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(&w.fx.app.pool)
            .await
            .unwrap();
    assert_eq!(state, "starting");
    assert!(waiting.contains(&at(WAIT_MAX_SECS)), "{waiting}");
    let events = "SELECT count(*) FROM events WHERE kind = 'agent.state' AND payload LIKE ?";
    assert_eq!(w.count(events, &format!("%{}%", s.id)).await, 1);
    // The window ended: the pick takes the account and the wait is gone from the row.
    let later = at(WAIT_MAX_SECS + 1);
    assert_eq!(
        took(w.pick(&s.id, near_only, &later).await).account,
        near.id
    );
    let gone: Option<String> =
        sqlx::query_scalar("SELECT waiting FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(&w.fx.app.pool)
            .await
            .unwrap();
    assert_eq!(gone, None);
    let recovered = "SELECT count(*) FROM audit_events WHERE action = 'account.state_set' \
                     AND details LIKE '%\"recovered\"%' AND details LIKE ?";
    assert_eq!(
        w.count(recovered, "%\"source\":\"lazy\"%").await,
        1,
        "recovery is audited"
    );
}

fn budget<'a>(
    kind: &'static str,
    subject: &'a str,
    tokens: i64,
    usd: Option<i64>,
) -> NewBudget<'a> {
    NewBudget {
        kind,
        subject,
        company: None,
        period: "day",
        token_cap: tokens,
        usd_cap_micros: usd,
        warn_at_percent: None,
        hard_stop: true,
    }
}

#[tokio::test]
async fn a_pool_or_account_without_room_for_one_turn_is_skipped_for_the_next_entry() {
    let w = w().await;
    let (a, b, c) = (w.acct("a").await, w.acct("b").await, w.acct("c").await);
    let chain = [
        w.keys("one", &[a.id]).await,
        w.keys("two", &[b.id, c.id]).await,
    ];
    let (by, pool) = (&w.fx.dev.id, &w.fx.app.pool);
    // The first pool's own budget is spent: its entry is skipped, with the reason.
    let subject = chain[0].pool.to_string();
    budgets::set(pool, &budget("pool", &subject, 1000, None), by, BY, NOW)
        .await
        .unwrap();
    let s = w.session(&chain, &[]).await;
    let got = took(w.pick(&s.id, &chain, NOW).await);
    assert_eq!((got.account, got.pos), (b.id, 1));
    let r = exhausted(
        w.pick_p(&w.session(&chain[..1], &[]).await.id, &chain[..1], NOW, p())
            .await,
    );
    assert!(r[0].1.contains("out of budget"), "{r:?}");
    // An account's dollar budget below one turn of the model's price skips that account alone.
    let dollars = b.id.to_string();
    budgets::set(pool, &budget("account", &dollars, 0, Some(10)), by, BY, NOW)
        .await
        .unwrap();
    let s = w.session(&chain, &[]).await;
    let min = |_: &crate::store::alloc::Entry| 1_000_000u64;
    let serves = |_: &crate::store::alloc::Entry| -> Option<String> { None };
    let ask = crate::store::alloc::Ask {
        session: &s.id,
        runner: &w.vm.id,
        user: 1,
        chain: &chain,
        from_pos: 1,
        used_accounts: &[],
        skip_pools: &[],
        min_turn: &min,
        serves: &serves,
        wait_max_secs: WAIT_MAX_SECS,
        lost_after_secs: crate::store::alloc::LOST_AFTER_SECS,
    };
    let mut tx = begin_write(pool).await.unwrap();
    let got = crate::store::alloc::pick_in(&mut tx, &ask, NOW)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(took(got).account, c.id);
}

#[tokio::test]
async fn skip_pools_and_the_runner_placement_leave_an_entry_out_with_a_reason() {
    let w = w().await;
    let (a, b) = (w.acct("a").await, w.acct("b").await);
    let chain = [w.keys("one", &[a.id]).await, w.keys("two", &[b.id]).await];
    let s = w.session(&chain, &[]).await;
    let skip = [chain[0].pool];
    let got = took(
        w.pick_p(
            &s.id,
            &chain,
            NOW,
            P {
                skip: &skip,
                commit: false,
                ..p()
            },
        )
        .await,
    );
    assert_eq!((got.account, got.pos), (b.id, 1));
    let all = [chain[0].pool, chain[1].pool];
    let r = exhausted(
        w.pick_p(
            &s.id,
            &chain,
            NOW,
            P {
                skip: &all,
                commit: false,
                ..p()
            },
        )
        .await,
    );
    assert_eq!(r.len(), 2);
    assert!(
        r.iter().all(|(_, why)| why.contains("budget is spent")),
        "{r:?}"
    );
    // A runner that cannot serve an entry (here: nothing serves the first) skips only it.
    let min = |_: &crate::store::alloc::Entry| 0u64;
    let serves =
        |e: &crate::store::alloc::Entry| (e.pool == chain[0].pool).then(|| "no gateway".to_owned());
    let ask = crate::store::alloc::Ask {
        session: &s.id,
        runner: &w.vm.id,
        user: 1,
        chain: &chain,
        from_pos: 0,
        used_accounts: &[],
        skip_pools: &[],
        min_turn: &min,
        serves: &serves,
        wait_max_secs: WAIT_MAX_SECS,
        lost_after_secs: crate::store::alloc::LOST_AFTER_SECS,
    };
    let mut tx = begin_write(&w.fx.app.pool).await.unwrap();
    let got = crate::store::alloc::pick_in(&mut tx, &ask, NOW)
        .await
        .unwrap();
    assert_eq!(took(got).account, b.id);
}

#[tokio::test]
async fn a_subscription_session_is_metered_to_the_account_the_pick_wrote() {
    use ainkrad_proto::runner::Tokens;
    use ainkrad_proto::v2::{AgentEvents, AgentState};
    let w = w().await;
    let plan = w.sub("plan").await;
    let chain = [w.pool("plan", "claude-sub", &[plan.id]).await];
    let s = w.session(&chain, &[]).await;
    took(w.pick(&s.id, &chain, NOW).await);
    // The account is the row's own column, not what the secret names.
    sqlx::query("UPDATE core_agent_sessions SET secrets = '[]' WHERE id = ?")
        .bind(&s.id)
        .execute(&w.fx.app.pool)
        .await
        .unwrap();
    let ev = AgentEvents {
        session: s.id.clone(),
        state: AgentState::Running,
        last_seq: 0,
        entries: vec![],
        harness_session: None,
        usage: Some(Tokens {
            input: 10,
            output: 2,
            cache_read: 0,
            cache_write: 0,
            cost_usd_micros: None,
        }),
        outcome: None,
        gateway: vec![],
        plan_limit: None,
    };
    crate::store::agents::apply(&w.fx.app.pool, &s.id, &ev, NOW)
        .await
        .unwrap();
    let account: i64 =
        sqlx::query_scalar("SELECT account_id FROM core_cost_events WHERE session = ?")
            .bind(&s.id)
            .fetch_one(&w.fx.app.pool)
            .await
            .unwrap();
    assert_eq!(account, plan.id);
}
