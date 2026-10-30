//! Step-up and destructive routes (handshake spec §8, §17.12, §17.13, E1-09.3/.6): only the
//! step-up key over a Core challenge bound to the session elevates it; an elevation lasts
//! `auth.step_up_secs`, is replaced (never stacked or extended), carried to a refreshed session,
//! and lost on restart; every route the contract marks destructive is refused without one.

use super::*;

/// A device with `scopes` and a session that is **not** elevated; `stepup` says whether it
/// enrolled a step-up key.
pub(super) async fn plain(fx: &Fx, name: &str, scopes: &[&str], stepup: bool) -> TestDevice {
    let fp = &fx.app.auth.identity.fp;
    let dev = TestDevice::enroll_keys(
        &fx.app.pool,
        name,
        "device",
        scopes,
        fp,
        fx.clock.clone(),
        stepup,
    )
    .await;
    let s = fx.app.auth.issue_session(&dev.id, fx.clock.unix());
    dev.set_session(Some(s.id));
    dev
}

pub(super) async fn post(fx: &Fx, dev: &TestDevice, uri: &str, body: Value) -> (StatusCode, Value) {
    send(&fx.app, req(Method::POST, uri, Some(dev), Some(body))).await
}

pub(super) async fn challenge(fx: &Fx, dev: &TestDevice) -> String {
    let (s, b) = post(fx, dev, "/api/v1/auth/step-up/challenge", json!({})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    b["challenge"].as_str().unwrap().to_owned()
}

/// Steps `dev` up for real.
pub(super) async fn step_up(fx: &Fx, dev: &TestDevice) -> (StatusCode, Value) {
    let c = challenge(fx, dev).await;
    post(fx, dev, "/api/v1/auth/step-up", dev.stepup_body(&c)).await
}

fn code(r: &(StatusCode, Value)) -> (StatusCode, String) {
    (r.0, r.1["code"].as_str().unwrap_or_default().to_owned())
}

fn forbidden(c: &str) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, c.to_owned())
}

async fn rename(fx: &Fx, dev: &TestDevice, name: &str) -> (StatusCode, Value) {
    let uri = format!("/api/v1/devices/{}", dev.id);
    send(
        &fx.app,
        req(Method::PATCH, &uri, Some(dev), Some(json!({"name": name}))),
    )
    .await
}

#[tokio::test]
async fn a_step_up_elevates_the_session_for_destructive_routes_then_lapses() {
    let fx = fx().await;
    let mac = plain(&fx, "mac", &ALL, true).await;
    assert_eq!(
        code(&rename(&fx, &mac, "Mac").await),
        forbidden("step_up_required")
    );
    let (s, b) = step_up(&fx, &mac).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let until = crate::scheduler::iso_of_unix(fx.clock.unix() + 300);
    assert_eq!(b["elevated_until"], json!(super::super::types::ts(&until)));
    assert_eq!(rename(&fx, &mac, "Mac").await.0, StatusCode::OK);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'auth.step_up' \
         AND json_extract(details, '$.device') = ?",
    )
    .bind(&mac.id)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
    // Normal requests do not extend it; a second step-up replaces it, it never stacks.
    fx.clock.advance(200);
    fx.ok("/api/v1/me").await;
    let (_, b) = step_up(&fx, &mac).await;
    let until = crate::scheduler::iso_of_unix(fx.clock.unix() + 300);
    assert_eq!(b["elevated_until"], json!(super::super::types::ts(&until)));
    // A refreshed session carries it over, not extended (§6.2).
    let s = fx.app.auth.issue_session(&mac.id, fx.clock.unix() + 10);
    assert_eq!(s.elevated_until, Some(fx.clock.unix() + 300));
    // §17.12: past it, refused again.
    fx.clock.advance(300);
    assert_eq!(
        code(&rename(&fx, &mac, "Mac").await),
        forbidden("step_up_required")
    );
}

#[tokio::test]
async fn the_window_is_the_setting_and_a_restart_or_revocation_ends_it() {
    let mut fx = fx().await;
    let uri = "/api/v1/settings/server/auth.step_up_secs";
    let (s, b) = send(
        &fx.app,
        req(Method::PUT, uri, Some(&fx.dev), Some(json!({"value": 60}))),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, _) = send(
        &fx.app,
        req(Method::PUT, uri, Some(&fx.dev), Some(json!({"value": 901}))),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "bounded at 900");
    let mac = plain(&fx, "mac", &ALL, true).await;
    step_up(&fx, &mac).await;
    fx.clock.advance(59);
    assert_eq!(rename(&fx, &mac, "a").await.0, StatusCode::OK);
    fx.clock.advance(1);
    assert_eq!(
        code(&rename(&fx, &mac, "b").await),
        forbidden("step_up_required")
    );

    step_up(&fx, &mac).await;
    fx.restart();
    let s = fx.app.auth.issue_session(&mac.id, fx.clock.unix());
    mac.set_session(Some(s.id));
    assert_eq!(s.elevated_until, None, "lost with the process");
    assert_eq!(
        code(&rename(&fx, &mac, "c").await),
        forbidden("step_up_required")
    );
}

#[tokio::test]
async fn only_the_step_up_key_over_this_sessions_live_challenge_elevates() {
    let fx = fx().await;
    let mac = plain(&fx, "mac", &ALL, true).await;
    let failed = forbidden("step_up_failed");
    let session = mac.session.lock().unwrap().clone().unwrap();
    // §17.13: the routine key's signature is no step-up.
    let c = challenge(&fx, &mac).await;
    let m = crate::auth::stepup::message(&fx.app.auth.identity.fp, &mac.id, &session, &c);
    let routine = json!({"challenge": c, "stepup_sig": crate::auth::crypto::b64(&mac.sign(&m))});
    let r = post(&fx, &mac, "/api/v1/auth/step-up", routine).await;
    assert_eq!(code(&r), failed);
    // The challenge was spent by that attempt.
    let r = post(&fx, &mac, "/api/v1/auth/step-up", mac.stepup_body(&c)).await;
    assert_eq!(code(&r), failed, "single use");
    // A replaced challenge, an expired one, and one issued to another session.
    let old = challenge(&fx, &mac).await;
    challenge(&fx, &mac).await;
    let r = post(&fx, &mac, "/api/v1/auth/step-up", mac.stepup_body(&old)).await;
    assert_eq!(code(&r), failed, "replaced");
    let late = challenge(&fx, &mac).await;
    fx.clock.advance(61);
    let r = post(&fx, &mac, "/api/v1/auth/step-up", mac.stepup_body(&late)).await;
    assert_eq!(code(&r), failed, "expired");
    let other = fx.app.auth.issue_session(&mac.id, fx.clock.unix());
    let mine = fx
        .app
        .auth
        .stepup_challenge(&other.id, &mac.id, fx.clock.unix())
        .unwrap();
    let r = post(&fx, &mac, "/api/v1/auth/step-up", mac.stepup_body(&mine)).await;
    assert_eq!(code(&r), failed, "another session's");
    assert_eq!(
        code(&rename(&fx, &mac, "x").await),
        forbidden("step_up_required")
    );

    // A device that enrolled no step-up key can never elevate.
    let cli = plain(&fx, "cli", &ALL, false).await;
    assert_eq!(code(&step_up(&fx, &cli).await), failed);
    assert_eq!(
        code(&rename(&fx, &cli, "x").await),
        forbidden("step_up_required")
    );
    // And a runner cannot even ask.
    let runner = TestDevice::enroll(
        &fx.app.pool,
        "r",
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    runner.set_session(Some(
        fx.app.auth.issue_session(&runner.id, fx.clock.unix()).id,
    ));
    let r = post(&fx, &runner, "/api/v1/auth/step-up/challenge", json!({})).await;
    assert_eq!(code(&r), forbidden("forbidden_scope"));
}

#[tokio::test]
async fn failed_proofs_lock_step_up_persistently_visibly_and_clearably() {
    let mut fx = fx().await;
    let mac = plain(&fx, "mac", &ALL, true).await;
    let bad = |c: &str| json!({"challenge": c, "stepup_sig": "A".repeat(86)});
    for _ in 0..5 {
        let c = challenge(&fx, &mac).await;
        let r = post(&fx, &mac, "/api/v1/auth/step-up", bad(&c)).await;
        assert_eq!(code(&r), forbidden("step_up_failed"));
    }
    // Locked now, even with a good proof, and across a restart.
    assert_eq!(step_up(&fx, &mac).await.0, StatusCode::TOO_MANY_REQUESTS);
    fx.restart();
    let s = fx.app.auth.issue_session(&mac.id, fx.clock.unix());
    mac.set_session(Some(s.id));
    let s = fx.app.auth.issue_session(&fx.dev.id, fx.clock.unix());
    fx.app
        .auth
        .elevate(&s.id, &fx.dev.id, fx.clock.unix() + 3600);
    fx.dev.set_session(Some(s.id));
    assert_eq!(step_up(&fx, &mac).await.0, StatusCode::TOO_MANY_REQUESTS);
    let key = format!("stepup:{}", mac.id);
    let locks = fx.ok("/api/v1/auth/lockouts").await;
    assert_eq!(locks[0]["key"], json!(key), "{locks}");
    assert_eq!(locks[0]["strikes"], json!(1));
    let lockout: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'auth.lockout' \
         AND json_extract(details, '$.key') = ?",
    )
    .bind(&key)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(lockout, 1, "audited once, at lock time");
    // Clearing needs admin and a step-up; then the device elevates again.
    let clear = json!({"key": key});
    let r = post(&fx, &mac, "/api/v1/auth/lockouts/clear", clear.clone()).await;
    assert_eq!(code(&r), forbidden("step_up_required"));
    let r = post(&fx, &fx.dev, "/api/v1/auth/lockouts/clear", clear.clone()).await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    let r = post(&fx, &fx.dev, "/api/v1/auth/lockouts/clear", clear).await;
    assert_eq!(r.0, StatusCode::NOT_FOUND);
    assert_eq!(step_up(&fx, &mac).await.0, StatusCode::OK);
    assert_eq!(fx.ok("/api/v1/auth/lockouts").await, json!([]));
}

#[tokio::test]
async fn concurrent_bad_proofs_cannot_overrun_the_device_budget() {
    let fx = fx().await;
    let mac = plain(&fx, "mac", &ALL, true).await;
    // 20 sessions, each with a challenge, all proved at once with a bad signature.
    let mut bodies = Vec::new();
    for _ in 0..20 {
        let s = fx.app.auth.issue_session(&mac.id, fx.clock.unix());
        let c = fx
            .app
            .auth
            .stepup_challenge(&s.id, &mac.id, fx.clock.unix())
            .unwrap();
        bodies.push((s.id, json!({"challenge": c, "stepup_sig": "A".repeat(86)})));
    }
    let tasks = bodies.into_iter().map(|(s, body)| {
        mac.set_session(Some(s));
        let r = req(Method::POST, "/api/v1/auth/step-up", Some(&mac), Some(body));
        let app = fx.app.clone();
        tokio::spawn(async move { send(&app, r).await.0 })
    });
    let mut evaluated = 0;
    for t in tasks.collect::<Vec<_>>() {
        evaluated += usize::from(t.await.unwrap() == StatusCode::FORBIDDEN);
    }
    assert_eq!(evaluated, 5, "the rest are 429 without being evaluated");
}

/// Every route the contract marks destructive (§17.11 for step-up, E1-09.6): an admin device
/// without an elevation gets 403 `step_up_required`, and the same device elevated never does.
#[tokio::test]
async fn every_destructive_operation_needs_a_live_elevation() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    let mut flagged = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            if op.get("x-ainkrad-destructive") == Some(&json!(true)) {
                flagged.push((method.to_uppercase(), path.clone()));
            }
        }
    }
    let listed: Vec<(String, String)> = super::super::scopes::DESTRUCTIVE
        .iter()
        .map(|(m, p)| ((*m).to_owned(), (*p).to_owned()))
        .collect();
    flagged.sort();
    let mut want = listed.clone();
    want.sort();
    assert_eq!(
        flagged, want,
        "the contract flags exactly the destructive list"
    );
    let mac = plain(&fx, "mac", &ALL, true).await;
    let other = plain(&fx, "other", &ALL, true).await;
    for (m, path) in &flagged {
        let uri = path
            .replace("{id}", &other.id)
            .replace("{scope}", "server")
            .replace("{key}", "api.request_burst");
        let body = Some(json!({"name": "x", "scopes": ["read"], "kind": "device", "value": 120}));
        let r = send(&fx.app, req(m.parse().unwrap(), &uri, Some(&mac), body)).await;
        assert_eq!(code(&r), forbidden("step_up_required"), "{m} {uri}");
    }
    assert_eq!(step_up(&fx, &mac).await.0, StatusCode::OK);
    for (m, path) in &flagged {
        let uri = path
            .replace("{id}", &other.id)
            .replace("{scope}", "server")
            .replace("{key}", "api.request_burst");
        let body = Some(
            json!({"name": "x", "scopes": ["read"], "kind": "device", "value": 120,
            "key": "ip:203.0.113.9", "sas": "AAAA-AAAA-AAAA-AAAA"}),
        );
        let r = send(&fx.app, req(m.parse().unwrap(), &uri, Some(&mac), body)).await;
        assert_ne!(r.1["code"], json!("step_up_required"), "{m} {uri}: {r:?}");
        assert_ne!(r.1["code"], json!("forbidden_scope"), "{m} {uri}: {r:?}");
    }
}

/// Pairing enrols the step-up key (§7.2 step 3), and never the routine key a second time.
#[tokio::test]
async fn pairing_enrols_a_second_key_never_the_routine_key_twice() {
    use crate::auth::crypto::{b64, fingerprint};
    use crate::auth::pairing::{code_hash, normal_code, pop_message};
    let fx = fx().await;
    let body = json!({"name": "New", "kind": "device", "scopes": ["read"]});
    let (s, created) = post(&fx, &fx.dev, "/api/v1/pairings", body).await;
    assert_eq!(s, StatusCode::OK, "{created}");
    let code = created["code"].as_str().unwrap();
    let dev = TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone());
    let claim = |stepup: &[u8], sign: &dyn Fn(&[u8]) -> Vec<u8>| {
        let hash = code_hash(&normal_code(code).unwrap());
        let fp = fingerprint(&dev.spki);
        let m = pop_message(&dev.core_fp, &hash, &fp, Some(&fingerprint(stepup)));
        let mut b = dev.claim_body(Some(code), None);
        b["pop"] = json!(b64(&dev.sign(&m)));
        b["stepup_spki"] = json!(b64(stepup));
        b["pop_stepup"] = json!(b64(&sign(&m)));
        req(Method::POST, "/pair/claim", None, Some(b))
    };
    let (s, b) = send(&fx.app, claim(&dev.spki, &|m| dev.sign(m))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    let (s, b) = send(&fx.app, claim(&dev.stepup_spki, &|m| dev.sign_stepup(m))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let row = crate::store::gov::get_device(&fx.app.pool, b["device_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.stepup_spki.as_deref(), Some(dev.stepup_spki.as_slice()));
}

/// E2-01, spec §17.11/§17.12: opening or attaching a terminal needs `terminal` and a live
/// elevation; `read` may only list; an expired elevation is refused again.
#[tokio::test]
async fn terminals_need_their_scope_and_a_live_step_up() {
    let fx = fx().await;
    let open = json!({"runner": "d_00000000000000000000000000", "size": {"rows": 24, "cols": 80}});
    let attach = |dev| {
        let uri = "/api/v1/terminals/t_x/ws";
        req(Method::GET, uri, Some(dev), None)
    };
    let phone = plain(&fx, "phone", &["read", "approve"], true).await;
    assert_eq!(
        code(&post(&fx, &phone, "/api/v1/terminals", open.clone()).await),
        forbidden("forbidden_scope")
    );
    assert_eq!(
        code(&send(&fx.app, attach(&phone)).await),
        forbidden("forbidden_scope")
    );
    let listed = send(
        &fx.app,
        req(Method::GET, "/api/v1/terminals", Some(&phone), None),
    )
    .await;
    assert_ne!(code(&listed), forbidden("forbidden_scope"));

    let mac = plain(&fx, "mac", &["read", "terminal"], true).await;
    assert_eq!(
        code(&post(&fx, &mac, "/api/v1/terminals", open.clone()).await),
        forbidden("step_up_required")
    );
    assert_eq!(
        code(&send(&fx.app, attach(&mac)).await),
        forbidden("step_up_required")
    );
    step_up(&fx, &mac).await;
    // Past the gate: the terminal service validates the runner before dispatch.
    let r = post(&fx, &mac, "/api/v1/terminals", open.clone()).await;
    assert_eq!(r.0, StatusCode::NOT_FOUND, "{r:?}");
    fx.clock.advance(301);
    assert_eq!(
        code(&post(&fx, &mac, "/api/v1/terminals", open).await),
        forbidden("step_up_required")
    );
}

#[tokio::test]
async fn another_device_cannot_read_a_terminal_by_id() {
    let fx = fx().await;
    let other = fx.enroll("other", &["read", "terminal"]).await;
    sqlx::query(
        "INSERT INTO core_terminals
         (user_id,id,runner,status,rows,cols,output_seq,opened_by,created_at,last_activity)
         VALUES (1,?,?,?,?,?,?,?,?,?)",
    )
    .bind("t_private")
    .bind(&fx.dev.id)
    .bind("running")
    .bind(24_i64)
    .bind(80_i64)
    .bind(0_i64)
    .bind(&fx.dev.id)
    .bind(NOW)
    .bind(fx.clock.unix())
    .execute(&fx.app.pool)
    .await
    .unwrap();

    let response = send(
        &fx.app,
        req(
            Method::GET,
            "/api/v1/terminals/t_private",
            Some(&other),
            None,
        ),
    )
    .await;
    assert_eq!(response.0, StatusCode::NOT_FOUND, "{response:?}");
}
