//! C6: seeded random walks with a fake clock. One walks the connection health state machine
//! (signals of both trust levels, tests, stale verdicts, replacements, time) and checks the rules
//! after EVERY step; the other walks bindings, defaults and deletes against a small model.
//!
//! A failing run prints its seed and step; `CORE_C6_SEED=<n>` replays that one.

use std::collections::BTreeMap;

use ainkrad_proto::v2::UpstreamStatus as U;

use super::*;
use crate::connections::adapter::Identity;
use health::Signal;
use verdict::TestOutcome;

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from((self.0 >> 33) % n as u64).unwrap()
    }

    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())]
    }
}

fn seeds(default: &[u64]) -> Vec<u64> {
    match std::env::var("CORE_C6_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(s) => vec![s],
        None => default.to_vec(),
    }
}

type Row4 = (String, Option<String>, Option<String>, i64);

/// status, reason, until, backoff, read raw.
async fn raw(fx: &Fx, id: i64) -> Row4 {
    sqlx::query_as(
        "SELECT status, state_reason, state_until, backoff_secs FROM core_connections WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&fx.pool)
    .await
    .unwrap()
}

const STATUSES: [&str; 5] = ["active", "cooling", "limited", "unhealthy", "disabled"];
const UPSTREAM: [U; 9] = [
    U::Ok,
    U::RateLimited,
    U::Quota,
    U::ServerError,
    U::Unreachable,
    U::TlsFailed,
    U::RefusedAddress,
    U::AuthFailed,
    U::Unknown,
];
const AGENT: [&str; 6] = [
    "rate_limited",
    "quota",
    "auth_failed",
    "disabled",
    "unhealthy",
    "",
];

async fn health_walk(seed: u64) {
    let mut r = Rng(seed);
    let fx = fx().await;
    let c = make(&fx, "fake", "walk").await;
    let id = c.id;
    let mut t: i64 = 0;
    let mut fresh = 0;
    for step in 0..120 {
        let now = at(t);
        let tag = format!("seed {seed} step {step} t={t}");
        // The lazy recovery runs first, as every real look would.
        health::recover(&fx.pool, id, &now).await.unwrap();
        let before = raw(&fx, id).await;
        let was = get(&fx.pool, 1, id).await.unwrap();
        let op = r.below(9);
        let mut name = "time";
        match op {
            0 | 1 => {
                name = "upstream";
                let status = r.pick(&UPSTREAM);
                let retry_after = r.pick(&[None, Some(5), Some(90_000_000)]);
                let sg = Signal::Upstream {
                    status,
                    retry_after,
                    reset_at: None,
                };
                health::signal(&fx.pool, 1, id, sg, &now).await.unwrap();
                let after = raw(&fx, id).await;
                if status == U::AuthFailed && before.0 != "disabled" {
                    assert_eq!(after.1.as_deref(), Some("auth_suspected"), "{tag}");
                    let now_row = get(&fx.pool, 1, id).await.unwrap();
                    let refused = verdict::usable(&now_row).unwrap_err();
                    assert_eq!(refused.0, "auth_pending", "{tag}");
                }
                if before.0 == "disabled" {
                    assert_eq!(after.0, "disabled", "{tag}: a signal re-enabled it");
                }
            }
            2 | 3 => {
                name = "agent";
                let class = r.pick(&AGENT);
                health::signal(&fx.pool, 1, id, Signal::Agent { class }, &now)
                    .await
                    .unwrap();
                let after = raw(&fx, id).await;
                assert_eq!(after.3, before.3, "{tag}: an agent moved the backoff");
                if before.0 != "active" {
                    assert_eq!(after, before, "{tag}: an agent changed a set state");
                } else {
                    assert!(
                        matches!(after.1.as_deref(), None | Some("rate_limited" | "quota")),
                        "{tag}: an agent's word made {:?}",
                        after.1
                    );
                    assert!(after.0 != "disabled" && after.0 != "unhealthy", "{tag}");
                }
            }
            4 => {
                name = "success";
                health::signal(&fx.pool, 1, id, Signal::Success, &now)
                    .await
                    .unwrap();
                let after = raw(&fx, id).await;
                assert_eq!(
                    (&after.0, &after.1),
                    (&before.0, &before.1),
                    "{tag}: a success moved the state"
                );
            }
            5 => {
                name = "test";
                let v = version(&fx, id).await;
                let out = match r.below(3) {
                    0 => TestOutcome::Passed(Identity {
                        subject: "acct".to_owned(),
                    }),
                    1 => TestOutcome::Rejected,
                    _ => TestOutcome::Inconclusive,
                };
                let rejected = out == TestOutcome::Rejected;
                let passed = matches!(out, TestOutcome::Passed(_));
                verdict::record_test(&fx.pool, id, v, out, ww(1, &now))
                    .await
                    .unwrap();
                let after = raw(&fx, id).await;
                if rejected {
                    assert_eq!(
                        (after.0.as_str(), after.1.as_deref()),
                        ("disabled", Some("auth_failed")),
                        "{tag}"
                    );
                }
                if passed {
                    assert!(
                        !matches!(after.1.as_deref(), Some("auth_suspected" | "auth_failed")),
                        "{tag}: a passing test left an auth state"
                    );
                }
            }
            6 => {
                name = "stale test";
                if fresh > 0 {
                    // A verdict on the credential before the last replacement.
                    let v = version(&fx, id).await - 1;
                    for out in [TestOutcome::Rejected, TestOutcome::Inconclusive] {
                        let got = verdict::record_test(&fx.pool, id, v, out, ww(1, &now)).await;
                        assert_eq!(code(got), "conflict", "{tag}");
                    }
                    assert_eq!(
                        raw(&fx, id).await,
                        before,
                        "{tag}: a stale verdict changed it"
                    );
                }
            }
            7 => {
                name = "replace";
                fresh += 1;
                let m = material(&format!("c6walk-credential-{seed}-{step}"));
                secret::replace(&fx.pool, &fx.sealer, id, &m, ww(1, &now))
                    .await
                    .unwrap();
                let after = raw(&fx, id).await;
                assert!(
                    !matches!(after.1.as_deref(), Some("auth_suspected" | "auth_failed")),
                    "{tag}: a new credential kept the old verdict"
                );
            }
            _ => t += 1 + i64::try_from(r.below(1500)).unwrap(),
        }
        // Whatever happened: a known state; `disabled` only by a rejected test (or already so);
        // a timed state ends in the future and within the longest cap.
        let after = raw(&fx, id).await;
        let tag = format!("{tag} after {name}");
        assert!(STATUSES.contains(&after.0.as_str()), "{tag}: {}", after.0);
        if after.0 == "disabled" && before.0 != "disabled" {
            assert_eq!(
                name, "test",
                "{tag}: disabled by something other than a test"
            );
        }
        if was.status == "disabled" && after.0 != "disabled" {
            assert!(
                matches!(name, "test" | "replace"),
                "{tag}: left `disabled` by {name}"
            );
        }
        health::recover(&fx.pool, id, &at(t)).await.unwrap();
        let settled = raw(&fx, id).await;
        if let (Some(reason), Some(until)) = (settled.1.as_deref(), settled.2.as_deref()) {
            let until = crate::scheduler::unix_secs(until).unwrap();
            let base = crate::scheduler::unix_secs(NOW).unwrap();
            assert!(
                until > base + t,
                "{tag}: {reason} ends at or before now but stays"
            );
            assert!(
                until <= base + t + 7 * 24 * 3600,
                "{tag}: {reason} lasts too long"
            );
        }
    }
}

#[tokio::test]
async fn the_health_state_machine_keeps_its_rules_over_random_walks() {
    for seed in seeds(&[7, 11, 19, 23, 42, 101, 2026, 4242]) {
        health_walk(seed).await;
    }
}

async fn defaults_walk(seed: u64) {
    let mut r = Rng(seed);
    let fx = fx().await;
    second_user(&fx).await;
    // Live connections (id -> kind) and the workspace default per kind, as the model has them.
    let mut live: BTreeMap<i64, &'static str> = BTreeMap::new();
    let mut default: BTreeMap<&'static str, i64> = BTreeMap::new();
    let mut n = 0;
    for step in 0..150 {
        let ids: Vec<i64> = live.keys().copied().collect();
        let tag = format!("seed {seed} step {step}");
        match r.below(6) {
            0 if live.len() < 10 => {
                let kind = r.pick(&["fake", "other"]);
                n += 1;
                let c = make(&fx, kind, &format!("c{n}")).await;
                live.insert(c.id, kind);
            }
            1 if !ids.is_empty() => {
                let id = r.pick(&ids);
                let kind = live[&id];
                let got = delete(&fx.pool, id, w(NOW)).await;
                match default.get(kind) == Some(&id) {
                    true => assert_eq!(code(got), "conflict", "{tag}: deleted a default"),
                    false => {
                        got.unwrap_or_else(|e| panic!("{tag}: {e}"));
                        live.remove(&id);
                    }
                }
            }
            2 if !ids.is_empty() => {
                let id = r.pick(&ids);
                bind(&fx, id, ("workspace", "")).await;
                default.insert(live[&id], id);
            }
            3 => {
                let kind = r.pick(&["fake", "other"]);
                let had = bindings::clear(&fx.pool, kind, ("workspace", ""), w(NOW))
                    .await
                    .unwrap();
                assert_eq!(had, default.remove(kind).is_some(), "{tag}");
            }
            4 if !ids.is_empty() => {
                // The unused scopes are stored and go with their connection.
                let id = r.pick(&ids);
                let scope = r.pick(&[("project", "p1"), ("agent", "bot"), ("session", "s1")]);
                bind(&fx, id, scope).await;
            }
            5 if !ids.is_empty() => {
                // Another workspace's id is never a default of ours.
                let id = r.pick(&ids);
                let got = bindings::set(&fx.pool, id, ("workspace", ""), ww(2, NOW)).await;
                assert_eq!(code(got), "not_found", "{tag}");
            }
            _ => {}
        }
        // The model and the store agree, a default is a live connection of its own kind, and
        // nothing refers to a connection that is gone.
        let all = bindings::list(&fx.pool, 1, None).await.unwrap();
        let stored: BTreeMap<String, i64> = all
            .iter()
            .filter(|b| b.scope_kind == "workspace")
            .map(|b| (b.kind.clone(), b.connection_id))
            .collect();
        let model: BTreeMap<String, i64> =
            default.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect();
        assert_eq!(stored, model, "{tag}");
        for b in &all {
            assert_eq!(
                live.get(&b.connection_id),
                Some(&b.kind.as_str()),
                "{tag}: {b:?}"
            );
        }
        let listed: Vec<i64> = list(&fx.pool, 1, None)
            .await
            .unwrap()
            .iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(listed, live.keys().copied().collect::<Vec<_>>(), "{tag}");
    }
}

#[tokio::test]
async fn bindings_defaults_and_deletes_keep_their_rules_over_random_walks() {
    for seed in seeds(&[3, 14, 15, 92, 653, 5897]) {
        defaults_walk(seed).await;
    }
}
