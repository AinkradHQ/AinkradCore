//! Account health from the harness's output (KAN-438 S3): a subscription session's end and its
//! plan snapshot. The output is forgeable, so it may only cool an account or count toward
//! `auth_suspected`; it never disables one, never reaches another account, and only the closed
//! `ErrorClass` set is a signal. The gateway's channel is `health.rs`.

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::{AgentEvents, AgentState, PlanLimit, PlanWindow};
use serde_json::{Value, json};

use super::accounts_store::setup;
use super::gateway_store::gw as fixture;
use super::health::{BY, at, counts, state_rows, view};
use super::*;
use crate::scheduler::unix_secs;
use crate::store::agents::{self as store, NewSession, SessionSecret};
use crate::store::{accounts as acc, health, settings};

const TOKEN: &str = "sk-ant-oat01-TESTONLY0123456789abcdefghijklmnop";
const TOKEN2: &str = "sk-ant-oat01-TESTONLY9876543210zyxwvutsrqponmlkj";

// ---- the harness channel (subscriptions) ---------------------------------------------------

struct S {
    fx: Fx,
    a: acc::Account,
    b: acc::Account,
    sa: store::Session,
    sb: store::Session,
}

async fn session(fx: &Fx, runner: &str, secrets: &[SessionSecret]) -> store::Session {
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets,
        created_by: &fx.dev.id,
    };
    store::create(&fx.app.pool, &new, BY, NOW).await.unwrap()
}

fn sub(a: &acc::Account) -> SessionSecret {
    SessionSecret {
        name: a.secret_name.clone(),
        var: "CLAUDE_CODE_OAUTH_TOKEN".to_owned(),
    }
}

/// Two subscription accounts, a session on each.
async fn subs() -> S {
    let (fx, vm, sealer) = setup().await;
    let gate = settings::set(
        &fx.app.pool,
        Key::SecretsProviderAccounts,
        Scope::Server,
        "1",
        BY,
        NOW,
    );
    gate.await.unwrap();
    let mut made = Vec::new();
    for (label, value) in [("claude-me", TOKEN), ("claude-two", TOKEN2)] {
        let new = acc::NewAccount {
            provider: "claude-sub",
            label,
            value,
            runners: std::slice::from_ref(&vm.id),
            cap: None,
        };
        made.push(
            acc::create_by(
                &fx.app.pool,
                &sealer,
                &new,
                "subscription",
                &fx.dev.id,
                BY,
                NOW,
            )
            .await
            .unwrap(),
        );
    }
    let (b, a) = (made.pop().unwrap(), made.pop().unwrap());
    let sa = session(&fx, &vm.id, &[sub(&a)]).await;
    let sb = session(&fx, &vm.id, &[sub(&b)]).await;
    S { fx, a, b, sa, sb }
}

async fn end(s: &S, session: &str, outcome: Value, secs: i64) {
    store::end(&s.fx.app.pool, session, "ended", &outcome, &at(secs))
        .await
        .unwrap();
}

fn failed(fingerprint: &str) -> Value {
    json!({"kind": "failed", "reason": "x", "fingerprint": fingerprint})
}

/// A fresh session on the account, ended with `outcome` (a session ends once).
async fn attempt(s: &S, a: &acc::Account, outcome: Value, secs: i64) {
    let id = session(&s.fx, &s.fx.dev.id, &[sub(a)]).await.id;
    end(s, &id, outcome, secs).await;
}

#[tokio::test]
async fn three_failed_auth_sessions_in_a_row_keep_a_subscription_out_and_a_success_resets() {
    let s = subs().await;
    let id = s.a.id;
    attempt(&s, &s.a, failed("auth"), 0).await;
    attempt(&s, &s.a, failed("auth"), 10).await;
    assert_eq!(
        (view(&s.fx, id).await.0, counts(&s.fx, id).await.1),
        ("active".into(), 2)
    );
    // Another class, a cancel, and a step name neither count nor reset.
    attempt(&s, &s.a, failed("permanent"), 15).await;
    attempt(&s, &s.a, json!({"kind": "cancelled", "reason": "me"}), 16).await;
    assert_eq!(counts(&s.fx, id).await.1, 2);
    // A success between: the count starts again.
    attempt(&s, &s.a, json!({"kind": "succeeded"}), 20).await;
    assert_eq!(counts(&s.fx, id).await.1, 0);
    for n in 0..3 {
        attempt(&s, &s.a, failed("auth"), 30 + n).await;
    }
    let (state, reason, until) = view(&s.fx, id).await;
    assert_eq!(
        (state.as_str(), reason.as_deref(), until),
        ("unhealthy", Some("auth_suspected"), None)
    );
    // It has no end: lazy recovery never lifts it, and it cannot start a run.
    health::recover(&s.fx.app.pool, id, &at(999_999))
        .await
        .unwrap();
    assert_eq!(view(&s.fx, id).await.0, "unhealthy");
    assert!(!health::startable("unhealthy", true));
    // The other account never saw any of it.
    assert_eq!(
        (view(&s.fx, s.b.id).await.0, counts(&s.fx, s.b.id).await),
        ("active".into(), (0, 0, 0))
    );
}

#[tokio::test]
async fn its_fine_resets_the_streak_and_is_audited_and_disable_is_the_users_alone() {
    let s = subs().await;
    let id = s.a.id;
    for n in 0..3 {
        attempt(&s, &s.a, failed("auth"), n).await;
    }
    let a = acc::set_state(
        &s.fx.app.pool,
        id,
        "active",
        None,
        None,
        &s.fx.dev.id,
        BY,
        &at(50),
    )
    .await
    .unwrap();
    assert_eq!(a.state, "active");
    assert_eq!(counts(&s.fx, id).await, (0, 0, 0));
    let row: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'account.state_set' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&s.fx.app.pool)
    .await
    .unwrap();
    assert!(
        row.contains("\"was\":\"auth_suspected\"") && row.contains("\"to\":\"active\""),
        "{row}"
    );
    // Two more failures after "it's fine" are 2, not 5.
    attempt(&s, &s.a, failed("auth"), 60).await;
    attempt(&s, &s.a, failed("auth"), 61).await;
    assert_eq!(
        (view(&s.fx, id).await.0, counts(&s.fx, id).await.1),
        ("active".into(), 2)
    );
}

#[tokio::test]
async fn forged_harness_signals_never_disable_and_unknown_fingerprints_are_ignored() {
    let s = subs().await;
    let id = s.a.id;
    // Not a class of the closed set: nothing, whatever it looks like.
    for f in [
        "core",
        "isolation",
        "sandbox",
        "fallback_exhausted",
        "harness_exit",
        "harness_dropped",
        "claude:401",
        "claude:rate_limited",
        "Auth",
        "auth ",
        "QUOTA",
        "rate_limit",
        "",
    ] {
        for _ in 0..4 {
            attempt(&s, &s.a, failed(f), 0).await;
        }
    }
    assert_eq!(
        (view(&s.fx, id).await.0, counts(&s.fx, id).await),
        ("active".into(), (0, 0, 0))
    );
    // Disabled, and an admin's own state, survive every class a harness can end with.
    for (state, reason) in [("disabled", "mine"), ("cooling", "my own pause")] {
        acc::set_state(
            &s.fx.app.pool,
            id,
            state,
            Some(reason),
            Some(&at(99_999)),
            "d",
            BY,
            &at(1),
        )
        .await
        .unwrap();
        for c in health::CLASSES {
            for n in 0..4 {
                attempt(&s, &s.a, failed(c), 2 + n).await;
            }
        }
        let a = view(&s.fx, id).await;
        assert_eq!((a.0.as_str(), a.1.as_deref()), (state, Some(reason)));
    }
    // A forged end cannot disable even from active: the worst state any class reaches is timed or
    // auth_suspected, never `disabled`.
    acc::set_state(&s.fx.app.pool, id, "active", None, None, "d", BY, &at(3))
        .await
        .unwrap();
    for c in health::CLASSES {
        for n in 0..4 {
            attempt(&s, &s.a, failed(c), 10 + n).await;
        }
    }
    assert_ne!(view(&s.fx, id).await.0, "disabled");
}

#[tokio::test]
async fn harness_cooling_is_bounded_and_never_extends_an_open_window() {
    let s = subs().await;
    let id = s.a.id;
    attempt(&s, &s.a, failed("rate_limited"), 0).await;
    assert_eq!(
        view(&s.fx, id).await,
        ("cooling".into(), Some("rate_limited".into()), Some(at(60)))
    );
    // Another forged one inside the window is no extension and no doubling.
    attempt(&s, &s.a, failed("rate_limited"), 10).await;
    assert_eq!(
        (view(&s.fx, id).await.2, counts(&s.fx, id).await.2),
        (Some(at(60)), 60)
    );
    // quota raises it, for six hours at most.
    attempt(&s, &s.a, failed("quota"), 20).await;
    assert_eq!(
        view(&s.fx, id).await,
        (
            "limited".into(),
            Some("quota".into()),
            Some(at(20 + 6 * 3600))
        )
    );
}

fn plan(status: &str, util: f64, resets: Option<i64>) -> PlanLimit {
    PlanLimit {
        status: status.to_owned(),
        windows: vec![PlanWindow {
            name: "five_hour".to_owned(),
            utilization: util,
            resets_at: resets,
        }],
    }
}

async fn snapshot(s: &S, id: &str, claimed: &str, p: PlanLimit, secs: i64) {
    let ev = AgentEvents {
        session: claimed.to_owned(),
        state: AgentState::Running,
        last_seq: 0,
        entries: vec![],
        harness_session: None,
        usage: None,
        outcome: None,
        gateway: vec![],
        plan_limit: Some(p),
    };
    store::apply(&s.fx.app.pool, id, &ev, &at(secs))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_plan_snapshot_cools_the_sessions_own_account_once_and_clamps_the_reset() {
    let s = subs().await;
    let (ia, ib) = (s.a.id, s.b.id);
    let reset = unix_secs(NOW).unwrap() + 5 * 3600;
    // The apply is for session A; the event's own `session` field names B, and means nothing.
    snapshot(
        &s,
        &s.sa.id,
        &s.sb.id,
        plan("allowed_warning", 0.97, Some(reset)),
        0,
    )
    .await;
    assert_eq!(
        view(&s.fx, ia).await,
        (
            "cooling".into(),
            Some("rate_limited".into()),
            Some(at(5 * 3600))
        )
    );
    assert_eq!(
        view(&s.fx, ib).await.0,
        "active",
        "never an account the session does not hold"
    );
    // Below the line, or no reset in the future: nothing (and the same snapshot resent: no change).
    let rows = state_rows(&s.fx).await;
    snapshot(
        &s,
        &s.sa.id,
        &s.sa.id,
        plan("allowed_warning", 0.97, Some(reset)),
        5,
    )
    .await;
    assert_eq!(state_rows(&s.fx).await, rows);
    snapshot(&s, &s.sb.id, &s.sb.id, plan("allowed", 0.5, Some(reset)), 5).await;
    snapshot(
        &s,
        &s.sb.id,
        &s.sb.id,
        plan("allowed_warning", 0.99, Some(1)),
        5,
    )
    .await;
    assert_eq!(view(&s.fx, ib).await.0, "active");
    // Once per session: after the window ends, the same session's resent snapshot cannot re-cool.
    health::recover(&s.fx.app.pool, ia, &at(5 * 3600 + 1))
        .await
        .unwrap();
    snapshot(
        &s,
        &s.sa.id,
        &s.sa.id,
        plan("rejected", 1.0, Some(reset + 9000)),
        5 * 3600 + 2,
    )
    .await;
    assert_eq!(view(&s.fx, ia).await.0, "active");
    // A far reset is clamped to the harness ceiling.
    let far = unix_secs(NOW).unwrap() + 30 * 86_400;
    snapshot(&s, &s.sb.id, &s.sb.id, plan("rejected", 1.0, Some(far)), 10).await;
    assert_eq!(view(&s.fx, ib).await.2, Some(at(10 + 6 * 3600)));
}

#[tokio::test]
async fn a_gateway_sessions_harness_signals_are_ignored() {
    let g = fixture().await;
    let id = g.account.id;
    for c in ["quota", "rate_limited", "auth"] {
        for n in 0..4 {
            let s = super::gateway_store::session(
                &g.fx,
                &g.vm,
                &[super::gateway_store::secret(&g.account.secret_name)],
            )
            .await;
            store::end(&g.fx.app.pool, &s.id, "ended", &failed(c), &at(n))
                .await
                .unwrap();
        }
    }
    let ev = AgentEvents {
        session: g.session.id.clone(),
        state: AgentState::Running,
        last_seq: 0,
        entries: vec![],
        harness_session: None,
        usage: None,
        outcome: None,
        gateway: vec![],
        plan_limit: Some(plan("rejected", 1.0, Some(unix_secs(NOW).unwrap() + 60))),
    };
    store::apply(&g.fx.app.pool, &g.session.id, &ev, &at(0))
        .await
        .unwrap();
    assert_eq!(
        (view(&g.fx, id).await.0, counts(&g.fx, id).await),
        ("active".into(), (0, 0, 0))
    );
}

#[test]
fn only_a_resumed_run_may_start_in_a_cooldown() {
    assert!(health::startable("active", false));
    assert!(!health::startable("cooling", false) && health::startable("cooling", true));
    for st in ["limited", "unhealthy", "disabled"] {
        assert!(!health::startable(st, true) && !health::startable(st, false));
    }
}
