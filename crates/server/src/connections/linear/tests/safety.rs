//! Odd answers, addresses, and secrets: nothing panics, nothing but `api.linear.app` is reachable,
//! and no credential appears in an error, an audit row or a printed value.

use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::linear::http::Http;
use crate::connections::linear::{CallError, Limit};

/// One valid call of every operation.
fn every_op() -> Vec<(&'static str, Value)> {
    vec![
        ("linear.get_issue", json!({"id": "ENG-1"})),
        ("linear.search_issues", json!({})),
        ("linear.list_teams", json!({})),
        ("linear.list_workflow_states", json!({"team": "ENG"})),
        ("linear.list_projects", json!({})),
        ("linear.create_issue", json!({"team": "ENG", "title": "t"})),
        (
            "linear.update_issue",
            json!({"id": "ENG-1", "title": "t", "state_id": STATE_ID}),
        ),
        ("linear.add_comment", json!({"id": "ENG-1", "body": "b"})),
    ]
}

fn odd_data() -> Vec<Value> {
    let team = |t: Value| json!({"team": t, "id": ISSUE_ID, "identifier": 5});
    vec![
        json!({}),
        json!({"issue": null}),
        json!({"issue": 5}),
        json!({"issue": "ENG-1"}),
        json!({"issue": []}),
        json!({"issue": team(json!([]))}),
        json!({"issue": team(json!({"key": null}))}),
        json!({"issue": team(json!({"key": ["ENG"]}))}),
        json!({"issue": team(json!("ENG"))}),
        json!({"issues": 5}),
        json!({"issues": null}),
        json!({"issues": {"nodes": [null, 5, "x", [], {"team": {"key": null}}]}}),
        json!({"issues": {"nodes": {"0": {}}}}),
        json!({"teams": 5}),
        json!({"teams": {"nodes": [null, {"key": []}, {"key": 5}, 7]}}),
        json!({"teams": {"nodes": [{"key": "ENG", "projects": 5}, {"key": "ENG", "projects": {"nodes": [null, 5, {"id": 5}, {"id": null}]}}]}}),
        json!({"teams": {"nodes": [{"key": "ENG", "projects": {"nodes": [[], "p", {"id": "p1"}, {"id": "p1"}]}}]}}),
        json!({"workflowStates": 5}),
        json!({"workflowStates": {"nodes": {}}}),
        json!({"workflowStates": {"nodes": [null, {"team": 5}]}}),
        json!({"workflowState": 5}),
        json!({"workflowState": []}),
        json!({"issueCreate": []}),
        json!({"issueCreate": null}),
        json!({"issueCreate": {"success": "yes"}}),
        json!({"issueCreate": {"success": true}}),
        json!({"issueCreate": {"success": true, "issue": 5}}),
        json!({"issueUpdate": {"success": true, "issue": []}}),
        json!({"issueUpdate": null}),
        json!({"commentCreate": {"success": true, "comment": 5}}),
        json!({"commentCreate": 7}),
        json!({"viewer": 5}),
        json!({"a": {"b": {"c": {"d": {"e": [[[[[[[[[[1]]]]]]]]]]}}}}}),
        json!({"issue": {"team": {"key": "ENG"}, "id": 1e308, "identifier": -0.0}}),
        json!({"issue": {"team": {"key": "E\u{0}NG\u{202e}"}, "id": "\u{1F600}"}}),
    ]
}

#[tokio::test]
async fn no_operation_panics_on_odd_json_and_a_limited_one_never_passes_what_it_cannot_check() {
    let f = fx(false).await;
    let c = f.key().await;
    let limited = Limit::only(&["ENG".to_owned()]);
    for data in odd_data() {
        for d in docs::ALL {
            let body = Reply::data(data.clone());
            f.fake.on(&format!("GQL {}", d.name), move |_| body.clone());
        }
        for (op, args) in every_op() {
            for l in [&limited, &Limit::any()] {
                let r = run(&f, &c, l, op, args.clone()).await;
                // What is returned from a limited connection came from a readable answer whose
                // every team is inside the limit.
                if let (Ok(v), true) = (&r, l.limited()) {
                    let text = v.to_string();
                    assert!(!text.contains("OPS"), "{op} {data}: {text}");
                }
            }
        }
    }
    // Bodies that are not even JSON values the parser accepts: deep nesting, a lone bracket.
    for raw in [
        "[".repeat(5000).into_bytes(),
        b"{\"data\": ".to_vec(),
        vec![0xff, 0xfe, 0x00],
        b"null".to_vec(),
        b"\"just a string\"".to_vec(),
    ] {
        for d in docs::ALL {
            let mut body = Reply::json(200, Value::Null);
            body.raw = Some(raw.clone());
            f.fake.on(&format!("GQL {}", d.name), move |_| body.clone());
        }
        for (op, args) in every_op() {
            let r = run(&f, &c, &Limit::any(), op, args).await;
            assert!(r.is_err(), "{op}: {r:?}");
        }
    }
    assert_eq!(f.fake.bad(), 0);
}

#[test]
fn only_https_api_linear_app_can_be_called_and_the_authorize_host_never_is() {
    let h = Http::production();
    assert!(h.allows("https://api.linear.app/graphql"));
    assert!(h.allows("https://api.linear.app/oauth/token"));
    let at = '@';
    let userinfo = format!("https://user:pw{at}api.linear.app/graphql");
    let userinfo2 = format!("https://api.linear.app{at}evil.test/graphql");
    for url in [
        "https://linear.app/oauth/authorize",
        "https://linear.app/graphql",
        "https://api.linear.app.evil.test/graphql",
        "https://evil.test/api.linear.app",
        "https://evil.test/?h=api.linear.app",
        "https://eviltest-api.linear.app.evil.test/graphql",
        "https://xapi.linear.app/graphql",
        "https://sub.api.linear.app/graphql",
        "http://api.linear.app/graphql",
        "https://api.linear.app:8443/graphql",
        "https://127.0.0.1/graphql",
        "https://[::1]/graphql",
        "ftp://api.linear.app/graphql",
        "//api.linear.app/graphql",
        "api.linear.app/graphql",
        "",
        userinfo.as_str(),
        userinfo2.as_str(),
    ] {
        assert!(!h.allows(url), "{url}");
    }
    assert_eq!(h.api, "https://api.linear.app");
    assert_eq!(h.auth, "https://linear.app");
}

#[test]
fn the_production_authorize_address_is_linear_app_and_carries_no_secret() {
    let app = OAuthApp::new("client-id-8c41", CLIENT_SECRET, &[REDIRECT]).unwrap();
    let linear = Linear::new(Some(app));
    let s = linear.start(1, REDIRECT, None).unwrap();
    assert!(
        s.authorize_url
            .starts_with("https://linear.app/oauth/authorize?")
    );
    assert!(!s.authorize_url.contains(CLIENT_SECRET));
    assert!(!s.authorize_url.contains("api.linear.app"));
}

#[tokio::test]
async fn no_credential_appears_in_an_error_an_audit_row_or_a_printed_value() {
    let f = fx(true).await;
    // Linear echoes secrets in its messages; none may reach an error.
    let echo = format!("bad token {ACCESS} {REFRESH} {API_KEY} {CLIENT_SECRET} Bearer {ACCESS}");
    let loud = json!({"errors": [{"message": echo, "extensions": {"code": "FORBIDDEN"}}]});
    for d in docs::ALL {
        let b = loud.clone();
        f.fake.on(&format!("GQL {}", d.name), move |_| {
            Reply::json(200, b.clone())
        });
    }
    f.fake.on("POST /oauth/token", move |_| {
        Reply::json(
            400,
            json!({"error": "invalid_grant",
        "error_description": "refresh token ref1-91c4d2b7a6e1 is dead"}),
        )
    });
    let oauth_c = f.connect("o", "oauth", &oauth(ACCESS, REFRESH, 10)).await;
    let key_c = f.key().await;
    let mut printed = Vec::new();
    for c in [&oauth_c, &key_c] {
        for (op, args) in every_op() {
            let r = run(&f, c, &Limit::any(), op, args).await;
            if let Err(e) = r {
                printed.push(format!("{e} {e:?}"));
            }
        }
        let t = f.linear.test_connection(&f.cx(NOW), c.id).await.unwrap();
        printed.push(format!("{t:?}"));
    }
    let started = f.linear.start(1, REDIRECT, None).unwrap();
    let e = f
        .linear
        .finish(1, &started.state, "code", None, NOW)
        .await
        .unwrap_err();
    printed.push(format!("{e} {e:?}"));
    printed.push(f.audit_text().await);
    let m = oauth(ACCESS, REFRESH, 10);
    printed.push(format!(
        "{m:?} {m} {:?}",
        crate::connections::linear::unpack(&m)
    ));
    printed.push(format!(
        "{:?}",
        OAuthApp::new("id", CLIENT_SECRET, &[REDIRECT])
    ));
    printed.push(format!("{:?}", crate::connections::linear::unpack(&key())));
    let all = printed.join("\n");
    for secret in [ACCESS, REFRESH, API_KEY, CLIENT_SECRET] {
        assert!(!all.contains(secret), "{secret} leaked into: {all}");
    }
    // And the errors that were returned are the fixed ones.
    let r = run(
        &f,
        &key_c,
        &Limit::any(),
        "linear.get_issue",
        json!({"id": "ENG-1"}),
    )
    .await;
    assert_eq!(r, Err(CallError::Forbidden));
}
