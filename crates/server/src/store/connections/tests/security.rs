//! Review findings: workspaces, paths, stale verdicts, use records, agent signals, wiping.

use ainkrad_proto::v2::UpstreamStatus as U;

use super::*;
use health::Signal;
use verdict::TestOutcome;

fn lim(v: &[&str]) -> grants::Limits {
    grants::Limits::from([(
        "projects".to_owned(),
        v.iter().map(|s| (*s).to_owned()).collect(),
    )])
}

#[tokio::test]
async fn no_function_trusts_a_bare_id_from_another_workspace() {
    let fx = fx().await;
    second_user(&fx).await;
    let c = make(&fx, "fake", "a").await;
    grant_role(&fx, c.id, "member", None).await;
    bind(&fx, c.id, ("workspace", "")).await;
    let before = get(&fx.pool, 1, c.id).await.unwrap();
    let w2 = || ww(2, NOW);
    let id = c.id;
    let none = grants::Limits::new();
    let user = grants::NewGrant {
        grantee_kind: "user",
        grantee: "2",
        capabilities: None,
        limits: &none,
    };
    let m = material("c1probe-intruder-0001");
    let v = version(&fx, id).await;
    let ident = TestOutcome::Passed(crate::connections::adapter::Identity {
        subject: "x".into(),
    });
    // Each acts in workspace 2 on workspace 1's id: not found, nothing written.
    assert_eq!(code(get(&fx.pool, 2, id).await), "not_found");
    assert_eq!(
        code(update_label(&fx.pool, id, "hijack", w2()).await),
        "not_found"
    );
    assert_eq!(
        code(rename(&fx.pool, id, "hijack", w2()).await),
        "not_found"
    );
    assert_eq!(
        code(set_disabled(&fx.pool, id, true, w2()).await),
        "not_found"
    );
    assert_eq!(code(delete(&fx.pool, id, w2()).await), "not_found");
    assert_eq!(
        code(grants::set(&fx.pool, &fx.reg, id, &user, w2()).await),
        "not_found"
    );
    assert_eq!(
        code(grants::revoke(&fx.pool, id, ("role", "member"), w2()).await),
        "not_found"
    );
    assert!(grants::list(&fx.pool, 2, id).await.unwrap().is_empty());
    assert_eq!(
        code(secret::replace(&fx.pool, &fx.sealer, id, &m, w2()).await),
        "not_found"
    );
    assert_eq!(
        code(secret::open(&fx.pool, &fx.sealer, 2, id).await),
        "not_found"
    );
    assert_eq!(
        code(verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, id, w2()).await),
        "not_found"
    );
    assert_eq!(
        code(verdict::record_test(&fx.pool, id, v, ident, w2()).await),
        "not_found"
    );
    assert_eq!(
        code(bindings::set(&fx.pool, id, ("project", "p"), w2()).await),
        "not_found"
    );
    let sig = health::signal(
        &fx.pool,
        2,
        id,
        Signal::Upstream {
            status: U::AuthFailed,
            retry_after: None,
            reset_at: None,
        },
        NOW,
    )
    .await;
    assert!(sig.is_err());
    let c2 = Context {
        workspace: 2,
        ..cx("read_items")
    };
    let used = resolve::record_use(
        &fx.pool,
        &fx.reg,
        Some(id),
        "fake",
        ("fake.get_item", "ok", None),
        &c2,
    )
    .await;
    assert_eq!(code(used), "not_found");
    assert_eq!(
        get(&fx.pool, 1, id).await.unwrap(),
        before,
        "workspace 1's row is as it was"
    );
    assert_eq!(
        secret::open(&fx.pool, &fx.sealer, 1, id)
            .await
            .unwrap()
            .0
            .access(),
        SECRET
    );
    assert!(bindings::list(&fx.pool, 2, None).await.unwrap().is_empty());
    // A user grantee must belong to the connection's workspace.
    let r = grants::set(&fx.pool, &fx.reg, id, &user, w(NOW)).await;
    assert_eq!(code(r), "bad_request");
}

#[test]
fn a_prefix_limit_never_matches_a_path_that_climbs_or_is_empty() {
    let l = |v: &str| vec![v.to_owned()];
    for bad in [
        "acme/x/../../evil",
        "acme//evil",
        "acme/./x",
        "acme/..",
        "acme/",
    ] {
        assert!(!grants::value_matches(&l("acme/*"), bad), "{bad}");
        assert!(!valid_ref(bad), "{bad}");
    }
    assert!(grants::value_matches(&l("acme/*"), "acme/app/deep"));
    assert!(clean_path("a/b") && !clean_path("") && !clean_path("a//b") && !clean_path("../a"));
}

#[tokio::test]
async fn limits_and_resources_with_dot_segments_are_refused() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    for bad in ["acme/../x/*", "acme//x", "acme/./x", "../x", "a/b/../c"] {
        let l = lim(&[bad]);
        let new = grants::NewGrant {
            grantee_kind: "role",
            grantee: "member",
            capabilities: None,
            limits: &l,
        };
        let r = grants::set(&fx.pool, &fx.reg, c.id, &new, w(NOW)).await;
        assert_eq!(code(r), "bad_request", "{bad}");
    }
    let limits = lim(&["acme/*"]);
    let new = grants::NewGrant {
        grantee_kind: "role",
        grantee: "member",
        capabilities: None,
        limits: &limits,
    };
    grants::set(&fx.pool, &fx.reg, c.id, &new, w(NOW))
        .await
        .unwrap();
    for bad in ["acme/x/../../evil", "acme//evil"] {
        let at = Context {
            resource: Some(("projects", bad)),
            ..cx("read_items")
        };
        let r = resolve::resolve(&fx.pool, &fx.reg, "fake", &at, NOW).await;
        assert_eq!(code(r), "bad_request", "{bad}");
    }
    let ok = Context {
        resource: Some(("projects", "acme/app")),
        ..cx("read_items")
    };
    assert!(
        resolve::resolve(&fx.pool, &fx.reg, "fake", &ok, NOW)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_verdict_on_an_old_credential_is_dropped_whatever_the_order() {
    let fx = fx().await;
    let c = make_with(&fx, "fake", "a", "reject-me-0001").await;
    let old = version(&fx, c.id).await;
    // Ordering 1: the credential is replaced while the old one is tested.
    let fresh = Material::new("c1probe-fresh-0001", None, None).unwrap();
    secret::replace(&fx.pool, &fx.sealer, c.id, &fresh, w(NOW))
        .await
        .unwrap();
    let r = verdict::record_test(&fx.pool, c.id, old, TestOutcome::Rejected, w(&at(1))).await;
    assert_eq!(code(r), "conflict");
    assert_eq!(
        get(&fx.pool, 1, c.id).await.unwrap().status,
        "active",
        "the new credential is not disabled"
    );
    // Ordering 2: replaced twice; a verdict for the first or the second is just as stale.
    let mid = version(&fx, c.id).await;
    let third = Material::new("c1probe-fresh-0002", None, None).unwrap();
    secret::replace(&fx.pool, &fx.sealer, c.id, &third, w(NOW))
        .await
        .unwrap();
    for v in [old, mid] {
        let r = verdict::record_test(&fx.pool, c.id, v, TestOutcome::Rejected, w(&at(2))).await;
        assert_eq!(code(r), "conflict", "v{v}");
    }
    let cur = version(&fx, c.id).await;
    let ok = verdict::record_test(&fx.pool, c.id, cur, TestOutcome::Rejected, w(&at(3)))
        .await
        .unwrap();
    assert_eq!(ok.status, "disabled", "a verdict on the current one counts");
    // The ordinary path still works end to end.
    let t = verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, c.id, w(&at(4)))
        .await
        .unwrap();
    assert_eq!(
        t.status, "active",
        "a passing test of the current credential clears it"
    );
}

async fn rec(
    fx: &Fx,
    id: i64,
    cx: &Context<'_>,
    op: &str,
) -> Result<(), crate::store::secrets::Error> {
    resolve::record_use(&fx.pool, &fx.reg, Some(id), "fake", (op, "ok", None), cx).await
}

#[tokio::test]
async fn a_use_record_takes_only_known_names_and_bounded_text() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let ok = cx("read_items");
    let long = "a".repeat(200);
    let evil = "x\"} injected {\"";
    assert!(rec(&fx, c.id, &ok, "fake.get_item").await.is_ok());
    for (bad, why) in [
        (
            Context {
                capability: "nope",
                ..ok
            },
            "capability not in the descriptor",
        ),
        (
            Context {
                agent: Some(evil),
                ..ok
            },
            "agent text",
        ),
        (
            Context {
                agent: Some(&long),
                ..ok
            },
            "agent length",
        ),
        (
            Context {
                session: Some(&long),
                ..ok
            },
            "session length",
        ),
        (
            Context {
                session: Some("../x"),
                ..ok
            },
            "session path",
        ),
    ] {
        assert_eq!(
            code(rec(&fx, c.id, &bad, "fake.get_item").await),
            "bad_request",
            "{why}"
        );
    }
    assert_eq!(
        code(rec(&fx, c.id, &ok, "fake.not_an_operation").await),
        "bad_request"
    );
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'connection.used'")
            .fetch_all(&fx.pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1, "only the valid one was written");
}

#[tokio::test]
async fn an_agents_word_never_outranks_the_cores_own() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let up = |status| Signal::Upstream {
        status,
        retry_after: None,
        reset_at: None,
    };
    let sig = |s: Signal<'static>, secs: i64| {
        let (pool, id) = (fx.pool.clone(), c.id);
        async move { health::signal(&pool, 1, id, s, &at(secs)).await.unwrap() }
    };
    // A trusted 60 s cooling is not turned into a 6 h limit by an agent.
    sig(up(U::RateLimited), 0).await;
    sig(Signal::Agent { class: "quota" }, 1).await;
    let after = get(&fx.pool, 1, c.id).await.unwrap();
    assert_eq!(
        (after.status.as_str(), after.state_reason.as_deref()),
        ("cooling", Some("rate_limited"))
    );
    assert_eq!(after.state_until.as_deref(), Some(at(60).as_str()));
    // Agent rate limits never move the backoff, however often they come.
    let d = make(&fx, "fake", "d").await;
    let backoff = |id| {
        let pool = fx.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT backoff_secs FROM core_connections WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    for round in 0..4 {
        let t = round * 1000;
        health::signal(
            &fx.pool,
            1,
            d.id,
            Signal::Agent {
                class: "rate_limited",
            },
            &at(t),
        )
        .await
        .unwrap();
        health::signal(
            &fx.pool,
            1,
            d.id,
            Signal::Agent {
                class: "rate_limited",
            },
            &at(t + 1),
        )
        .await
        .unwrap();
        assert_eq!(backoff(d.id).await, 0, "round {round}");
    }
    let s = get(&fx.pool, 1, d.id).await.unwrap();
    assert_eq!(
        s.state_until.as_deref(),
        Some(at(3060).as_str()),
        "the second word did not extend the window"
    );
}

#[tokio::test]
async fn nothing_decrypts_while_the_broker_is_off() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    crate::store::settings::set(
        &fx.pool,
        Key::SecretsMode,
        Scope::Server,
        "0",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    // A box that could not open the row: a refusal for the mode proves the check came first.
    let wrong = SecretBox::new(&[9; 32]);
    assert_eq!(
        code(secret::open(&fx.pool, &wrong, 1, c.id).await),
        "secrets_disabled"
    );
    assert_eq!(
        code(secret::open(&fx.pool, &fx.sealer, 1, c.id).await),
        "secrets_disabled"
    );
    let r = verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, c.id, w(NOW)).await;
    assert_eq!(code(r), "secrets_disabled");
    crate::store::settings::set(
        &fx.pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    assert!(secret::open(&fx.pool, &fx.sealer, 1, c.id).await.is_ok());
}

async fn db_bytes(fx: &Fx) -> Vec<u8> {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&fx.pool)
        .await
        .unwrap();
    std::fs::read(fx.dir.join("core.db")).unwrap()
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn a_replaced_or_deleted_credential_leaves_no_sealed_bytes_behind() {
    let fx = fx().await;
    let sealed = |id| {
        let pool = fx.pool.clone();
        async move {
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT sealed FROM core_connection_secrets WHERE connection_id = ?",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let c = make(&fx, "fake", "a").await;
    let v1 = sealed(c.id).await;
    assert!(
        has(&db_bytes(&fx).await, &v1),
        "the test can see a live blob"
    );
    let fresh = Material::new("c1probe-fresh-0003", None, None).unwrap();
    secret::replace(&fx.pool, &fx.sealer, c.id, &fresh, w(NOW))
        .await
        .unwrap();
    let v2 = sealed(c.id).await;
    let file = db_bytes(&fx).await;
    assert!(!has(&file, &v1), "the replaced blob is gone from the file");
    assert!(has(&file, &v2));
    delete(&fx.pool, c.id, w(NOW)).await.unwrap();
    assert!(
        !has(&db_bytes(&fx).await, &v2),
        "the deleted blob is gone from the file"
    );
}
