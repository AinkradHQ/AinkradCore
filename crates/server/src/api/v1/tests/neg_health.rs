//! S8, the health state machine: random signal sequences (gateway reports, harness ends, plan
//! snapshots, successes, an admin's holds, time) on one account with a fake clock. After every step:
//!
//! - no signal ever disables an account; an admin's hold is byte-identical through every signal and
//!   every recovery;
//! - an open window's end never moves back, and its rank never falls, until it recovers;
//! - a harness-sourced end is at most `HARNESS_MAX_SECS` away (any source: `QUOTA_MAX_SECS`);
//! - only the module's own codes ever appear, and `auth_suspected` only after `AUTH_LIMIT` harness
//!   `auth` ends with no success between, with no end of its own;
//! - a bystander account is never touched.
//!
//! The seed is in every message; `NEG_SEED=<n>` replays one seed.

use ainkrad_proto::v2::{PlanLimit, PlanWindow, UpstreamStatus};

use super::allocator::{W, w};
use super::health::at;
use super::neg_rng::{Rng, seeds};
use crate::scheduler::unix_secs;
use crate::store::{accounts as acc, begin_write, health};
use health::Signal;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

type Row = (String, Option<String>, Option<String>);

async fn row(w: &W, id: i64) -> (Row, i64) {
    let (s, r, u, auth): (String, Option<String>, Option<String>, i64) = sqlx::query_as(
        "SELECT state, state_reason, state_until, auth_streak FROM core_accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&w.fx.app.pool)
    .await
    .unwrap();
    ((s, r, u), auth)
}

fn rank(r: Option<&str>) -> i32 {
    match r {
        Some("rate_limited") => 1,
        Some("upstream_errors") => 2,
        Some("quota") => 3,
        Some("auth_suspected") => 4,
        _ => 0,
    }
}

fn unix(s: &str) -> i64 {
    unix_secs(s).unwrap()
}

async fn send(w: &W, id: i64, session: &str, sig: Signal<'_>, now: &str) {
    let mut tx = begin_write(&w.fx.app.pool).await.unwrap();
    health::on_signal(&mut tx, id, session, sig, now)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn walk(seed: u64, harness_only: bool) {
    let mut rng = Rng(seed);
    let w = w().await;
    let (a, b) = (w.acct("subject").await, w.acct("bystander").await);
    let s = w.session(&[], &[]).await;
    let pool = &w.fx.app.pool;
    let base = unix(super::NOW);
    let bystander = row(&w, b.id).await;
    let statuses = [
        UpstreamStatus::Ok,
        UpstreamStatus::RateLimited,
        UpstreamStatus::Quota,
        UpstreamStatus::AuthFailed,
        UpstreamStatus::ServerError,
        UpstreamStatus::Unreachable,
        UpstreamStatus::RefusedAddress,
        UpstreamStatus::TlsFailed,
        UpstreamStatus::Unknown,
    ];
    let classes = [
        "model_unavailable",
        "rate_limited",
        "quota",
        "auth",
        "auth",
        "transient",
        "unhealthy",
        "protocol",
        "permanent",
        "core",
        "isolation",
        "claude:401",
        "Auth",
        "",
    ];
    let (mut t, mut held, mut run, mut suspect_ok) = (0_i64, None::<Row>, 0_i64, false);
    for step in 0..140 {
        let ctx = format!("seed {seed} harness_only {harness_only} step {step}");
        let (pre, _) = row(&w, a.id).await;
        let now = at(t);
        let mut quiet = false;
        match rng.below(11) {
            0..=2 => {
                let class = classes[rng.below(classes.len())];
                if class == "auth" {
                    run += 1;
                    suspect_ok |= run >= health::AUTH_LIMIT;
                }
                send(&w, a.id, &s.id, Signal::HarnessEnd { class }, &now).await;
            }
            3 => {
                let status = ["rejected", "allowed", "allowed_warning"][rng.below(3)];
                let windows = (0..rng.below(3))
                    .map(|i| PlanWindow {
                        name: format!("w{i}"),
                        utilization: rng.int(0, 120) as f64 / 100.0,
                        resets_at: [
                            None,
                            Some(base + t - 50),
                            Some(base + t + rng.int(1, 10_000_000_000)),
                        ][rng.below(3)],
                    })
                    .collect();
                let plan = PlanLimit {
                    status: status.to_owned(),
                    windows,
                };
                sqlx::query("UPDATE core_agent_sessions SET plan_cooled = 0 WHERE id = ?")
                    .bind(&s.id)
                    .execute(pool)
                    .await
                    .unwrap();
                send(&w, a.id, &s.id, Signal::HarnessPlan { plan: &plan }, &now).await;
            }
            4 => {
                run = 0;
                send(&w, a.id, &s.id, Signal::Success, &now).await;
            }
            5 | 6 => {
                quiet = true;
                t += match rng.below(3) {
                    0 => rng.int(1, 200),
                    1 => rng.int(1, 4000),
                    _ => rng.int(1, 200_000),
                };
            }
            7 => {
                quiet = true;
                let state = ["cooling", "limited", "unhealthy", "disabled"][rng.below(4)];
                let opts = [
                    None,
                    Some(at(t - 10)),
                    Some(at(t + 500)),
                    Some(at(t + 1_000_000)),
                ];
                let until = opts[rng.below(4)].clone();
                let by = &w.fx.dev.id;
                acc::set_state(
                    pool,
                    a.id,
                    state,
                    Some("hold"),
                    until.as_deref(),
                    by,
                    BY,
                    &now,
                )
                .await
                .unwrap();
                held = Some(row(&w, a.id).await.0);
                suspect_ok = false;
            }
            8 if rng.below(2) == 0 => {
                quiet = true;
                let by = &w.fx.dev.id;
                acc::set_state(pool, a.id, "active", None, None, by, BY, &now)
                    .await
                    .unwrap();
                (held, run, suspect_ok) = (None, 0, false);
            }
            _ if harness_only => {
                send(
                    &w,
                    a.id,
                    &s.id,
                    Signal::HarnessEnd {
                        class: "rate_limited",
                    },
                    &now,
                )
                .await;
            }
            _ => {
                let status = statuses[rng.below(statuses.len())];
                if status == UpstreamStatus::Ok {
                    run = 0;
                }
                let retry_after =
                    [None, Some(30), Some(u64::MAX), Some(1_000_000_000_000)][rng.below(4)];
                let opts = [
                    None,
                    Some(at(t - 100)),
                    Some(at(t + rng.int(1, 2_000_000_000))),
                    Some("junk".to_owned()),
                ];
                let reset = opts[rng.below(4)].clone();
                let sig = Signal::Gateway {
                    status,
                    retry_after,
                    reset_at: reset.as_deref(),
                };
                send(&w, a.id, &s.id, sig, &now).await;
            }
        }
        let (post, auth) = row(&w, a.id).await;
        let admin_disabled = held.as_ref().is_some_and(|h| h.0 == "disabled");
        assert!(
            post.0 != "disabled" || admin_disabled,
            "a signal disabled it, {ctx}"
        );
        assert_eq!(
            auth, run,
            "the auth streak is the harness auth ends since a success, {ctx}"
        );
        if let Some(h) = &held {
            assert_eq!(&post, h, "an admin's hold changed, {ctx}");
        } else {
            let own = [
                None,
                Some("rate_limited"),
                Some("upstream_errors"),
                Some("quota"),
                Some("auth_suspected"),
            ];
            assert!(
                own.contains(&post.1.as_deref()),
                "a code that is not the module's: {post:?}, {ctx}"
            );
            let open = pre.2.as_deref().is_none_or(|u| unix(u) > base + t);
            if !quiet && pre.0 != "active" && open {
                assert_ne!(post.0, "active", "an open window closed early, {ctx}");
                assert!(
                    rank(post.1.as_deref()) >= rank(pre.1.as_deref()),
                    "rank fell {pre:?} -> {post:?}, {ctx}"
                );
                match (&pre.2, &post.2) {
                    (Some(p), Some(q)) => assert!(unix(q) >= unix(p), "a window shortened, {ctx}"),
                    (None, q) => assert!(q.is_none(), "an open-ended state got an end, {ctx}"),
                    (Some(_), None) => {
                        assert_eq!(post.1.as_deref(), Some("auth_suspected"), "{ctx}")
                    }
                }
            }
            if let Some(u) = &post.2 {
                let max = if harness_only {
                    health::HARNESS_MAX_SECS
                } else {
                    health::QUOTA_MAX_SECS
                };
                assert!(
                    unix(u) <= base + t + max,
                    "an end past the bound {post:?}, {ctx}"
                );
            }
            if post.1.as_deref() == Some("auth_suspected") {
                assert!(
                    suspect_ok,
                    "auth_suspected without {} auth ends, {ctx}",
                    health::AUTH_LIMIT
                );
                assert_eq!(
                    (post.0.as_str(), post.2.as_deref()),
                    ("unhealthy", None),
                    "{ctx}"
                );
            }
        }
        assert_eq!(
            row(&w, b.id).await,
            bystander,
            "the bystander changed, {ctx}"
        );
    }
    // A week on: every window of the module's own has recovered; a hold and `auth_suspected` have not.
    health::recover(pool, a.id, &at(t + 8 * 86_400))
        .await
        .unwrap();
    let (end, _) = row(&w, a.id).await;
    match &held {
        Some(h) => assert_eq!(&end, h, "a recovery touched a hold, seed {seed}"),
        None => assert!(
            end.0 == "active" || end.1.as_deref() == Some("auth_suspected"),
            "{end:?} did not recover, seed {seed}"
        ),
    }
}

#[tokio::test]
async fn neg_a_harness_only_signal_walk_never_disables_never_outruns_its_bound_and_never_moves_a_hold()
 {
    for seed in seeds(&[1, 2, 3, 4, 5, 6, 7, 8]) {
        walk(seed, true).await;
    }
}

#[tokio::test]
async fn neg_a_mixed_signal_walk_keeps_every_window_and_every_hold() {
    for seed in seeds(&[11, 12, 13, 14, 15, 16, 17, 18]) {
        walk(seed, false).await;
    }
}
