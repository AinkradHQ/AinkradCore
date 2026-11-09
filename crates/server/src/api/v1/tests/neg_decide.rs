//! S8: the failover decision function fuzzed: a Core end, a lost runner, a session's own limit and a
//! forged fingerprint never move a run, and a gateway's own report outranks what the harness printed.

use serde_json::json;

use super::neg_rng::{Rng, seeds};
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
        outcome: None,
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

#[test]
fn neg_the_decision_never_moves_on_a_core_end_a_lost_runner_or_a_forged_name() {
    for seed in seeds(&[1, 2, 3]) {
        let mut rng = Rng(seed);
        let kinds = [
            "succeeded",
            "failed",
            "cancelled",
            "token_cap",
            "stalled",
            "weird",
        ];
        let prints = [
            "core",
            "rate_limited",
            "quota",
            "auth",
            "transient",
            "permanent",
            "unhealthy",
            "protocol",
            "model_unavailable",
            "harness_exit",
            "claude:401",
            "Auth",
            "",
            "fallback_exhausted",
        ];
        let ups = [
            None,
            Some("ok"),
            Some("rate_limited"),
            Some("quota"),
            Some("auth_failed"),
            Some("server_error"),
            Some("refused_address"),
            Some("tls_failed"),
            Some("nonsense"),
        ];
        for _ in 0..4000 {
            let mut v = view();
            let pick = |rng: &mut Rng, n: usize| rng.below(n);
            v.state = ["ended", "lost"][pick(&mut rng, 2)].into();
            let print = prints[pick(&mut rng, prints.len())];
            v.outcome =
                Some(json!({"kind": kinds[pick(&mut rng, kinds.len())], "fingerprint": print}));
            v.class = [None, Some("quota".to_owned())][pick(&mut rng, 2)].clone();
            v.upstream = ups[pick(&mut rng, ups.len())].map(str::to_owned);
            v.gw_stop = [None, Some("budget".to_owned())][pick(&mut rng, 2)].clone();
            v.budget = [
                None,
                Some(fo::BudgetStop::Pool(3)),
                Some(fo::BudgetStop::Account(4)),
            ][pick(&mut rng, 3)];
            v.gateway = pick(&mut rng, 2) == 0;
            v.module = pick(&mut rng, 5) == 0;
            v.chain = (pick(&mut rng, 6) != 0).then(Vec::new);
            v.account = (pick(&mut rng, 6) != 0).then_some(1);
            let kind = v.outcome.as_ref().unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned();
            let d = fo::decide(&v);
            let ctx = format!("seed {seed} {v:?}");
            if v.module
                || v.chain.is_none()
                || v.account.is_none()
                || v.state == "lost"
                || ["succeeded", "token_cap", "stalled"].contains(&kind.as_str())
                || print == "core"
            {
                assert!(matches!(d, Decision::End(_)), "moved: {ctx}");
            }
            if v.gw_stop.is_some() && v.budget.is_none() {
                assert!(
                    matches!(d, Decision::End(_)),
                    "a session's own limit moved: {ctx}"
                );
            }
            if let Decision::Move(c) = &d {
                let closed = fo::FALLS_BACK.contains(&c.as_str())
                    || ["upstream_errors", "budget_pool"].contains(&c.as_str());
                assert!(
                    closed || v.class.as_deref() == Some(c.as_str()),
                    "a class outside the set moved a run: {ctx}"
                );
                if v.class.is_none() && v.budget.is_none() && kind != "failed" {
                    panic!("only a failed end moves with no decision written: {ctx}");
                }
            }
            // A gateway attempt that has its own report ignores what the harness printed.
            if v.gateway && v.upstream.is_some() {
                let mut other = v.clone();
                other.outcome = Some(json!({"kind": kind, "fingerprint": "rate_limited"}));
                if print != "core" && print != "rate_limited" {
                    assert_eq!(
                        fo::decide(&other),
                        d,
                        "the harness overruled the gateway: {ctx}"
                    );
                }
            }
        }
    }
}
