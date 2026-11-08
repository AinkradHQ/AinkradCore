//! Slack through the API, second half (C9): a pasted bot token, replacing a token, a rotating
//! app below `secrets.mode` 2, and sign-in switched off without stopping renewal.

use super::*;

#[tokio::test]
async fn a_bot_token_is_tested_at_once_and_only_a_bot_of_one_workspace_is_kept() {
    let (c, l) = scx().await;
    let made = c.ok(Method::POST, URI, token_body("mine", TOK)).await;
    assert_eq!(
        (&made["kind"], &made["auth_method"]),
        (&json!("slack"), &json!("token"))
    );
    assert_eq!(made["identity"], IDENTITY);
    assert_eq!(
        l.fake.last("auth.test").unwrap().auth,
        Some(format!("Bearer {TOK}"))
    );
    // A token that is not a bot token, or not usable text, is refused before Slack is asked.
    let before = l.fake.seen().len();
    for bad in [
        "",
        "has space in it",
        "short",
        "xoxp-test-111-222-user",
        "xoxe.xoxb-test-111-222-rot",
        "xoxe-1-test-ref",
    ] {
        let r = c.admin(Method::POST, URI, token_body("bad", bad)).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{bad:?}: {}", r.1);
    }
    assert_eq!(l.fake.seen().len(), before);
    // A token Slack refuses is not stored; nor is one that turns out to be no bot.
    l.fake.reply("auth.test", st::Reply::err("invalid_auth"));
    let r = c
        .admin(Method::POST, URI, token_body("refused", TOK2))
        .await;
    assert_eq!(code(&r), (400, "credential_rejected".to_owned()), "{}", r.1);
    let mut no_bot = st::auth_test(st::TEAM);
    no_bot.as_object_mut().unwrap().remove("bot_id");
    l.fake.reply("auth.test", st::Reply::ok(no_bot));
    let r = c.admin(Method::POST, URI, token_body("nobot", TOK2)).await;
    assert_eq!(code(&r), (400, "credential_rejected".to_owned()), "{}", r.1);
    assert_eq!(connections(&c).await.len(), 1);
    c.assert_clean_also(&[TOK, TOK2]).await;
}

#[tokio::test]
async fn replacing_a_token_stays_in_the_workspace_and_a_connection_without_one_is_not_replaced() {
    let (c, l) = scx().await;
    let made = c.ok(Method::POST, URI, token_body("mine", TOK)).await;
    let id = made["id"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| made["id"].to_string());
    let path = format!("{URI}/{id}/credential");
    // Another workspace's bot: refused, and the stored token is still the first (the next call
    // goes out with it).
    l.fake
        .reply("auth.test", st::Reply::ok(st::auth_test("T999AB3CD")));
    let r = c.admin(Method::PUT, &path, json!({"token": TOK2})).await;
    assert_eq!(code(&r), (409, "different_account".to_owned()), "{}", r.1);
    l.fake
        .reply("auth.test", st::Reply::ok(st::auth_test(st::TEAM)));
    c.ok(Method::POST, &format!("{URI}/{id}/test"), Value::Null)
        .await;
    assert_eq!(
        l.fake.last("auth.test").unwrap().auth,
        Some(format!("Bearer {TOK}"))
    );
    // The same workspace: replaced, and the connection is tested with the new token.
    let r = c.ok(Method::PUT, &path, json!({"token": TOK2})).await;
    assert_eq!(r["identity"], IDENTITY);
    assert_eq!(
        l.fake.last("auth.test").unwrap().auth,
        Some(format!("Bearer {TOK2}"))
    );
    // Not a bot token, a rotating one, a user's, or a token that is no bot: refused.
    for bad in [
        "xoxp-test-111-222-user",
        "xoxe.xoxb-test-111-222-rot",
        "short",
    ] {
        let r = c.admin(Method::PUT, &path, json!({"token": bad})).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{bad}: {}", r.1);
    }
    let mut no_bot = st::auth_test(st::TEAM);
    no_bot.as_object_mut().unwrap().remove("bot_id");
    l.fake.reply("auth.test", st::Reply::ok(no_bot));
    let r = c.admin(Method::PUT, &path, json!({"token": TOK})).await;
    assert_eq!(code(&r), (400, "credential_rejected".to_owned()), "{}", r.1);
    l.fake
        .reply("auth.test", st::Reply::ok(st::auth_test(st::TEAM)));
    // With no recorded workspace there is nothing to compare: refused, not let through.
    sqlx::query("UPDATE core_connections SET identity = NULL")
        .execute(&c.fx.app.pool)
        .await
        .unwrap();
    let r = c.admin(Method::PUT, &path, json!({"token": TOK})).await;
    assert_eq!(code(&r), (409, "identity_unknown".to_owned()), "{}", r.1);
    c.assert_clean_also(&[TOK, TOK2]).await;
}

#[tokio::test]
async fn a_slack_app_with_token_rotation_is_refused_at_start_below_mode_2_before_a_code_is_spent() {
    use ainkrad_core::audit::AuditActor;
    use ainkrad_core::settings::{Key, Scope};
    let (c, l) = scx().await;
    configure_with(&c, json!({"token_rotation": "true"})).await;
    let r = begin(&c, json!({})).await;
    assert_eq!(code(&r), (409, "needs_mode_2".to_owned()), "{}", r.1);
    assert_eq!((l.slack.pending(), l.fake.count("oauth.v2.access")), (0, 0));
    // Rotation off in the Slack app: the default flow starts at mode 1.
    configure_with(&c, json!({"token_rotation": "false"})).await;
    let (s, v) = begin(&c, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    c.admin(
        Method::DELETE,
        &format!("{URI}/flows/{}", v["id"].as_str().unwrap()),
        Value::Null,
    )
    .await;
    // Rotation on at mode 2: it starts.
    configure_with(&c, json!({"token_rotation": "true"})).await;
    let set = crate::store::settings::set(
        &c.fx.app.pool,
        Key::SecretsMode,
        Scope::Server,
        "2",
        AuditActor::System,
        super::super::NOW,
    );
    set.await.unwrap();
    let (s, v) = begin(&c, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(l.fake.bad(), 0);
    c.assert_clean().await;
}

/// A Slack app with rotation on, signed in once: its tokens are real-shaped-free test ones.
async fn rotating_connection(c: &Cx, l: &st::Fx) -> i64 {
    use ainkrad_core::audit::AuditActor;
    use ainkrad_core::settings::{Key, Scope};
    let set = crate::store::settings::set(
        &c.fx.app.pool,
        Key::SecretsMode,
        Scope::Server,
        "2",
        AuditActor::System,
        super::super::NOW,
    );
    set.await.unwrap();
    configure_with(c, json!({"token_rotation": "true"})).await;
    l.fake.on("oauth.v2.access", |s| {
        let refreshing = s.form.get("grant_type").is_some();
        let (access, refresh) = match refreshing {
            true => ("xoxe.xoxb-test-111-222-acc2", "xoxe-1-test-ref2-91c4d2"),
            false => ("xoxe.xoxb-test-111-222-acc1", "xoxe-1-test-ref1-91c4d2"),
        };
        st::Reply::ok(json!({"access_token": access, "refresh_token": refresh,
            "token_type": "bot", "bot_user_id": st::BOT_USER,
            "team": {"id": st::TEAM, "name": "Acme"}, "expires_in": 43200}))
    });
    let done = sign_in(c, json!({})).await;
    assert_eq!(done["step"], "connected", "{done}");
    done["connection"].as_i64().unwrap()
}

async fn make_due(c: &Cx, id: i64) {
    let q = "UPDATE core_connection_secrets SET expires_at = '2020-01-01T00:00:00.000Z' \
             WHERE connection_id = ?";
    sqlx::query(q)
        .bind(id)
        .execute(&c.fx.app.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn switching_sign_in_off_does_not_switch_the_renewal_of_existing_connections_off() {
    use crate::connections::slack::Ctx;
    use crate::store::connections::Who;
    let (c, l) = scx().await;
    let id = rotating_connection(&c, &l).await;
    // No catcher page: Add to Slack is off and a start says so ...
    let off = json!({"fields": {"catcher_ready": "false"}});
    assert_eq!(c.ok(Method::PUT, APPS, off).await["configured"], false);
    let r = begin(&c, json!({})).await;
    assert_eq!(code(&r), (409, "not_configured".to_owned()), "{}", r.1);
    let kinds = c
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let k = kinds
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["kind"] == "slack")
        .unwrap();
    assert_eq!(k["auth_methods"][0]["available"], false);
    // ... but the connection already made is renewed with the app's id and secret.
    make_due(&c, id).await;
    let t = c
        .ok(Method::POST, &format!("{URI}/{id}/test"), Value::Null)
        .await;
    assert_eq!(
        (&t["status"], &t["identity"]),
        (&json!("active"), &json!(IDENTITY)),
        "{t}"
    );
    let sent = l.fake.last("oauth.v2.access").unwrap().form;
    assert_eq!(sent["grant_type"], "refresh_token");
    assert_eq!(sent["refresh_token"], "xoxe-1-test-ref1-91c4d2");
    assert_eq!(sent["client_secret"], CLIENT_SECRET);
    // The redirect cleared altogether: still renewed.
    let cleared = json!({"fields": {"redirect_uri": null}});
    assert_eq!(c.ok(Method::PUT, APPS, cleared).await["configured"], false);
    make_due(&c, id).await;
    let ws: i64 = sqlx::query_scalar("SELECT user_id FROM core_connections WHERE id = ?")
        .bind(id)
        .fetch_one(&c.fx.app.pool)
        .await
        .unwrap();
    let who = Who {
        workspace: ws,
        by_device: "d_test",
        actor: ainkrad_core::audit::AuditActor::System,
        now: super::super::NOW,
    };
    let sealer = c.fx.app.secrets.as_ref().unwrap();
    let cx = Ctx {
        pool: &c.fx.app.pool,
        sealer,
        who,
    };
    let m = c.fx.app.connections.slack().fresh(&cx, id).await.unwrap();
    assert_eq!(m.refresh(), Some("xoxe-1-test-ref2-91c4d2"));
    assert_eq!(
        l.fake.count("oauth.v2.access"),
        3,
        "one sign-in and two renewals"
    );
    // The app removed altogether is the only thing that stops it.
    let gone = json!({"fields": {"client_id": null, "client_secret": null}});
    c.ok(Method::PUT, APPS, gone).await;
    make_due(&c, id).await;
    let e =
        c.fx.app
            .connections
            .slack()
            .fresh(&cx, id)
            .await
            .map(|_| ())
            .unwrap_err();
    assert_eq!(e.code(), "not_configured");
    c.assert_clean_also(&["xoxe.xoxb-test-111-222-acc1", "xoxe-1-test-ref1-91c4d2"])
        .await;
}
