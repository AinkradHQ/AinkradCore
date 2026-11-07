//! Second review: what a refused renewal may conclude, odd bodies, races between a renewal and a
//! person's new credential, a removed site, and what a limited answer is scanned for.

use serde_json::{Value, json};

use super::*;
use crate::connections::jira::{CallError, Limit};
use crate::store::connections::{create, get, secret};
use crate::store::secrets::Error;

fn limited(keys: &[&str]) -> Limit {
    Limit::only(&keys.iter().map(|k| (*k).to_owned()).collect::<Vec<_>>())
}

fn person() -> Material {
    oauth("acc7-person0a1b2c3d", "ref7-person0a1b2c3d", 3600)
}

#[tokio::test]
async fn a_wrong_client_secret_or_an_edge_refusal_disables_no_connection() {
    let f = fx(true).await;
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let cases = [
        (401, json!({"error": "invalid_client"})),
        (403, json!({"error": "unauthorized_client"})),
        (403, json!({"message": "blocked by the edge"})),
        (401, json!({})),
        (403, Value::Null),
        (400, json!({"error": "invalid_request"})),
        (400, json!({"error": "unsupported_grant_type"})),
    ];
    for (status, body) in cases {
        f.fake.reply("POST /oauth/token", status, body.clone());
        let t = f.jira.test_connection(&f.cx(NOW), c.id).await.unwrap();
        assert_eq!(t.status, "active", "{status} {body}");
    }
    // The app problem is visible as its own error, and gives no per-connection health signal.
    f.fake
        .reply("POST /oauth/token", 401, json!({"error": "invalid_client"}));
    let e = f
        .jira
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.code(), "app_config");
    assert!(e.health().is_none());
    // Only `invalid_grant` says THIS credential is dead, whatever status carries it.
    for status in [400, 401, 403] {
        let g = fx(true).await;
        g.fake.reply(
            "POST /oauth/token",
            status,
            json!({"error": "invalid_grant"}),
        );
        let c = g
            .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
            .await;
        let t = g.jira.test_connection(&g.cx(NOW), c.id).await.unwrap();
        assert_eq!(t.status, "disabled", "{status}");
    }
}

#[tokio::test]
async fn an_odd_2xx_body_never_panics_and_never_passes_a_limited_read() {
    let f = fx(false).await;
    let c = f.basic().await;
    let p = |rest: &str| site_path(rest);
    let keys = [
        format!("GET {}", p("/issue/ABC-1")),
        format!("GET {}", p("/issue/ABC-1/transitions")),
        format!("PUT {}", p("/issue/ABC-1")),
        format!("POST {}", p("/issue/ABC-1/comment")),
        format!("POST {}", p("/issue/ABC-1/transitions")),
        format!("POST {}", p("/issue")),
        format!("POST {}", p("/search/jql")),
        format!("GET {}", p("/project/search")),
    ];
    let ops = [
        ("jira.get_issue", json!({"key": "ABC-1"})),
        ("jira.search_issues", json!({})),
        ("jira.list_projects", json!({})),
        ("jira.list_transitions", json!({"key": "ABC-1"})),
        ("jira.update_issue", json!({"key": "ABC-1", "summary": "s"})),
        ("jira.add_comment", json!({"key": "ABC-1", "body": "b"})),
        (
            "jira.transition_issue",
            json!({"key": "ABC-1", "transition_id": "31"}),
        ),
        (
            "jira.create_issue",
            json!({"project": "ABC", "summary": "s", "issue_type": "Task"}),
        ),
    ];
    let bodies = [
        json!([]),
        json!("text"),
        json!(5),
        json!(true),
        Value::Null,
        json!([1, {"a": 2}]),
    ];
    for body in bodies {
        for k in &keys {
            f.fake.reply(k, 200, body.clone());
        }
        for (op, args) in &ops {
            let l = limited(&["ABC"]);
            let r = f.jira.call(&f.cx(NOW), &c, &l, op, args).await;
            if *op != "jira.create_issue" {
                assert!(r.is_err(), "{op} with {body} passed a limited call: {r:?}");
            }
            let _ = f.jira.call(&f.cx(NOW), &c, &Limit::any(), op, args).await;
        }
    }
}

#[tokio::test]
async fn a_renewal_never_overwrites_a_credential_a_person_stored_meanwhile() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let cx = f.cx(NOW);
    let who = cx.who;
    let renew = f.jira.fresh(&cx, c.id);
    let replace = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        secret::replace(&f.pool, &f.sealer, c.id, &person(), who)
            .await
            .unwrap();
    };
    let (m, ()) = tokio::join!(renew, replace);
    let m = m.unwrap();
    assert!(
        m.access().ends_with("acc7-person0a1b2c3d"),
        "the newer credential is what is returned"
    );
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert!(stored.access().ends_with("acc7-person0a1b2c3d"));
    assert_eq!(stored.refresh(), Some("ref7-person0a1b2c3d"));
    assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_refused_renewal_of_the_old_credential_does_not_condemn_the_new_one() {
    let f = fx(true).await;
    f.fake.on("POST /oauth/token", |_| {
        Reply::json(400, json!({"error": "invalid_grant"})).delayed(150)
    });
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let cx = f.cx(NOW);
    let who = cx.who;
    let test = f.jira.test_connection(&cx, c.id);
    let replace = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        secret::replace(&f.pool, &f.sealer, c.id, &person(), who)
            .await
            .unwrap();
    };
    let (t, ()) = tokio::join!(test, replace);
    t.unwrap();
    let now = get(&f.pool, 1, c.id).await.unwrap();
    assert_eq!(
        now.status, "active",
        "a verdict on version 1 must not settle version 2"
    );
}

#[tokio::test]
async fn a_site_the_account_lost_is_a_conclusive_rejection_and_a_failed_check_is_not_a_pass() {
    let f = fx(true).await;
    f.fake.reply(
        "GET /me",
        200,
        json!({"account_id": "5b10ac8d", "name": "Ann"}),
    );
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    let other = json!([{"id": "7d0c4b1e-0000-4000-8000-000000000001", "url": "https://x.atlassian.net", "name": "X", "scopes": ["read:jira-work"]}]);
    f.fake
        .reply("GET /oauth/token/accessible-resources", 200, other);
    let t = f.jira.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(t.status, "disabled", "the site is gone: reconnect");
    // The site is listed: it passes. The list could not be read: no verdict, and no identity.
    let g = fx(true).await;
    g.fake.reply(
        "GET /me",
        200,
        json!({"account_id": "5b10ac8d", "name": "Ann"}),
    );
    let c = g
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    for status in [500, 429, 401] {
        g.fake
            .reply("GET /oauth/token/accessible-resources", status, json!({}));
        let t = g.jira.test_connection(&g.cx(NOW), c.id).await.unwrap();
        assert_eq!(
            (t.status.as_str(), t.identity.is_none()),
            ("active", true),
            "{status}"
        );
    }
    let t = {
        g.fake.reply(
            "GET /oauth/token/accessible-resources",
            200,
            json!([{"id": CLOUD, "url": SITE, "name": "Acme", "scopes": []}]),
        );
        g.jira.test_connection(&g.cx(NOW), c.id).await.unwrap()
    };
    assert_eq!(
        t.identity.as_deref(),
        Some("5b10ac8d at https://acme.atlassian.net")
    );
}

#[tokio::test]
async fn without_an_app_an_expired_or_refused_token_is_an_auth_signal_not_an_internal_error() {
    let f = fx(false).await;
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let e = f
        .jira
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.code(), "oauth_not_configured");
    assert_eq!(
        e.health().map(|h| h.0),
        Some(ainkrad_proto::v2::UpstreamStatus::AuthFailed)
    );
    assert!(e.to_string().contains("not set up"));
    let g = fx(false).await;
    let c = g
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    g.fake.reply(
        &format!("GET {}", oauth_path("/issue/ABC-1")),
        401,
        json!({}),
    );
    let args = json!({"key": "ABC-1"});
    let e = g
        .jira
        .call(&g.cx(NOW), &c, &Limit::any(), "jira.get_issue", &args)
        .await;
    assert_eq!(e.unwrap_err().code(), "oauth_not_configured");
}

#[tokio::test]
async fn only_a_jira_connection_is_tested_by_the_jira_adapter() {
    let f = fx(true).await;
    let reg = crate::connections::fake::registry();
    let new = crate::store::connections::NewConnection {
        kind: "other",
        name: "x",
        label: "Another kind",
        auth_method: "token",
    };
    let m = Material::new("tok-abc12345", None, None).unwrap();
    let c = create(&f.pool, &f.sealer, &reg, &new, &m, f.cx(NOW).who)
        .await
        .unwrap();
    let r = f.jira.test_connection(&f.cx(NOW), c.id).await;
    assert!(
        matches!(
            r,
            Err(Error::Refused {
                code: "bad_request",
                ..
            })
        ),
        "{r:?}"
    );
}

#[tokio::test]
async fn a_short_lived_token_is_not_renewed_on_every_use() {
    let f = fx(true).await;
    f.fake.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": "acc8-0a1b2c3d4e5f", "refresh_token": "ref8-0a1b2c3d4e5f", "expires_in": 90}),
    );
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    f.jira.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(f.fake.count("POST /oauth/token"), 1);
    let soon = at(10);
    f.jira.fresh(&f.cx(&soon), c.id).await.unwrap();
    assert_eq!(
        f.fake.count("POST /oauth/token"),
        1,
        "80 s of a 90 s token left is not due"
    );
    let late = at(75);
    f.jira.fresh(&f.cx(&late), c.id).await.unwrap();
    assert_eq!(f.fake.count("POST /oauth/token"), 2, "15 s left is");
}

#[tokio::test]
async fn limited_answers_are_scanned_in_the_fields_that_carry_keys_not_in_free_text() {
    let f = fx(false).await;
    let c = f.basic().await;
    let l = limited(&["ABC"]);
    let one = format!("GET {}", site_path("/issue/ABC-1"));
    let get_issue = || async {
        f.jira
            .call(
                &f.cx(NOW),
                &c,
                &l,
                "jira.get_issue",
                &json!({"key": "ABC-1"}),
            )
            .await
    };
    let plain = json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"},
        "summary": "UTF-8, SHA-256 and see SECRET-5", "labels": ["ISO-8601"],
        "description": {"content": [{"text": "blocked by XYZ-9"}]}}});
    f.fake.reply(&one, 200, plain);
    get_issue().await.unwrap();
    let foreign = [
        json!({"key": "SECRET-1", "fields": {"project": {"key": "ABC"}}}),
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}, "parent": {"key": "SECRET-2"}}}),
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}, "subtasks": [{"key": "SECRET-3"}]}}),
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"},
            "issuelinks": [{"inwardIssue": {"key": "SECRET-4"}}]}}),
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"},
            "issuelinks": [{"outwardIssue": {"key": "SECRET-5"}}]}}),
        json!({"key": "not a key", "fields": {"project": {"key": "ABC"}}}),
    ];
    for body in foreign {
        f.fake.reply(&one, 200, body.clone());
        let r = get_issue().await;
        let Err(CallError::Refused(why)) = r else {
            panic!("{body}")
        };
        assert!(!why.contains("SECRET"), "{why}");
    }
    let key = format!("POST {}", site_path("/search/jql"));
    let hit = json!({"issues": [{"key": "SECRET-1", "fields": {"project": {"key": "ABC"}}}]});
    f.fake.reply(&key, 200, hit);
    let r = f
        .jira
        .call(&f.cx(NOW), &c, &l, "jira.search_issues", &json!({}))
        .await;
    assert!(matches!(r, Err(CallError::Refused(_))), "{r:?}");
}
