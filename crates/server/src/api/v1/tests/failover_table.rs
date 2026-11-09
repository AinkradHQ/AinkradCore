//! The failover decision table, row by row (KAN-438 S6; design §8.1), and the reading of a budget
//! stop. Pure: no database.

use serde_json::json;

use crate::store::failover::{self as fo, Decision, View};

fn view() -> View {
    View {
        id: "as_x".into(),
        n: 1,
        state: "ended".into(),
        runner: "d_r".into(),
        user: 1,
        run: "as_x".into(),
        attempt: 0,
        chain: Some(vec![]),
        pos: Some(0),
        account: Some(1),
        outcome: Some(json!({"kind": "failed", "fingerprint": "rate_limited"})),
        class: None,
        done: false,
        upstream: None,
        gw_stop: None,
        budget: None,
        gateway: false,
        module: false,
        skip_pools: vec![],
        created_by: "d_c".into(),
    }
}

fn kind(v: &mut View, k: &str, fingerprint: Option<&str>) {
    v.outcome = Some(json!({"kind": k, "fingerprint": fingerprint}));
}

fn moves(d: Decision) -> String {
    match d {
        Decision::Move(c) => c,
        Decision::End(why) => panic!("ended: {why}"),
    }
}

#[test]
fn the_decision_table_row_by_row() {
    let ends = |v: &View| assert!(matches!(fo::decide(v), Decision::End(_)), "{v:?}");
    // No chain to walk: a module's, a named account's, one that never had an account.
    for edit in [
        (|v: &mut View| v.module = true) as fn(&mut View),
        |v| v.chain = None,
        |v| v.account = None,
    ] {
        let mut v = view();
        edit(&mut v);
        ends(&v);
    }
    // 4: a lost session is the runner's failure, not the account's.
    let mut lost = view();
    lost.state = "lost".into();
    lost.class = Some("quota".into());
    ends(&lost);
    // 1: finished or limited by itself ends the run, even when a stop was ordered in the same breath.
    for k in ["succeeded", "token_cap", "stalled"] {
        let mut v = view();
        kind(&mut v, k, None);
        v.class = Some("quota".into());
        ends(&v);
    }
    // 0: the decision written before the stop moves it, though the runner calls the stop a cancel.
    let mut stopped = view();
    kind(&mut stopped, "cancelled", None);
    ends(&stopped);
    stopped.class = Some("quota".into());
    assert_eq!(moves(fo::decide(&stopped)), "quota");
    // 2: an account or pool budget moves the run; a session limit or ceiling ends it.
    let mut budget = view();
    kind(&mut budget, "cancelled", None);
    budget.gw_stop = Some("budget exhausted: pool 3 (day, 2026-11-06)".into());
    budget.budget = Some(fo::BudgetStop::Pool(3));
    assert_eq!(moves(fo::decide(&budget)), "budget_pool");
    budget.budget = Some(fo::BudgetStop::Account(9));
    assert_eq!(moves(fo::decide(&budget)), "budget_pool");
    // A ceiling or session-limit stop names no budget: it ends the run, even with a class on the row (G).
    budget.budget = None;
    budget.gw_stop =
        Some("the gateway's ceiling is used up and the budgets leave too little".into());
    ends(&budget);
    budget.class = Some("quota".into());
    ends(&budget);
    // 3: a gateway attempt is judged by the gateway's own reports.
    let mut gw = view();
    gw.gateway = true;
    for (up, class) in [
        ("rate_limited", Some("rate_limited")),
        ("quota", Some("quota")),
        ("auth_failed", Some("auth")),
        ("server_error", Some("upstream_errors")),
        ("unreachable", Some("upstream_errors")),
        ("tls_failed", Some("upstream_errors")),
        ("refused_address", None),
        ("ok", None),
    ] {
        gw.upstream = Some(up.into());
        match class {
            Some(c) => assert_eq!(moves(fo::decide(&gw)), c, "{up}"),
            None => ends(&gw),
        }
    }
    // ... and a forged harness class on a gateway attempt whose reports say `ok` moves nothing.
    gw.upstream = Some("ok".into());
    kind(&mut gw, "failed", Some("auth"));
    ends(&gw);
    // ... with no report at all, the harness's class counts (a model that is gone).
    gw.upstream = None;
    kind(&mut gw, "failed", Some("model_unavailable"));
    assert_eq!(moves(fo::decide(&gw)), "model_unavailable");
    // A subscription is judged by the harness's class, and only the closed set that falls back.
    let mut sub = view();
    for c in fo::FALLS_BACK {
        kind(&mut sub, "failed", Some(c));
        assert_eq!(moves(fo::decide(&sub)), c);
    }
    for c in [
        "transient",
        "permanent",
        "core",
        "fallback_exhausted",
        "harness_x",
        "claude:429",
        "step:plan",
    ] {
        kind(&mut sub, "failed", Some(c));
        ends(&sub);
    }
    kind(&mut sub, "failed", None);
    ends(&sub);
}

#[test]
fn a_budget_stop_is_read_from_the_code_the_core_wrote_with_it() {
    use fo::BudgetStop::{Account, Pool};
    assert_eq!(fo::budget_stop("pool:12"), Some(Pool(12)));
    assert_eq!(fo::budget_stop("account:4"), Some(Account(4)));
    for no in ["", "agent:4", "pool:x", "pool", "the ceiling is used up"] {
        assert_eq!(fo::budget_stop(no), None, "{no}");
    }
}

#[test]
fn the_cores_own_end_never_moves_a_run_whatever_class_the_attempt_last_saw() {
    let mut v = view();
    v.gateway = true;
    v.upstream = Some("rate_limited".into());
    kind(&mut v, "failed", Some("core"));
    assert!(matches!(fo::decide(&v), Decision::End(_)));
    v.class = Some("quota".into());
    assert!(matches!(fo::decide(&v), Decision::End(_)));
    v.gateway = false;
    v.upstream = None;
    v.class = None;
    assert!(matches!(fo::decide(&v), Decision::End(_)));
}
