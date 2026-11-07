//! The review findings of #148, each with its case.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;

use super::fake::Fake;
use crate::connections::github::device::{self, DeviceError, Step};
use crate::connections::github::http::{Host, NetError, Rate, Req, Resp};
use crate::connections::github::outcome::classify;
use crate::connections::github::{BuildError, Github, Outcome, build};
use crate::connections::material::Material;
use ainkrad_proto::v2::UpstreamStatus;

const TOKEN: &str = "ghp_testtoken1234";

fn gh(fake: &Fake) -> Github {
    Github::new(Arc::new(fake.transport()))
}

fn mat() -> Material {
    Material::new(TOKEN, None, None).unwrap()
}

fn resp(status: u16) -> Resp {
    Resp {
        status,
        rate: Rate::default(),
        scopes: None,
        body: zeroize::Zeroizing::new(Vec::new()),
    }
}

// 1: only GitHub's own trouble counts against a shared connection.
#[test]
fn replies_an_agent_can_provoke_never_signal_health() {
    for status in 100..=599u16 {
        let Err(o) = classify(&resp(status)) else {
            continue;
        };
        let counts = matches!(status, 401 | 429 | 500..=599);
        assert_eq!(o.health().is_some(), counts, "{status}: {o:?}");
    }
    for s in [301, 302, 307, 308, 413, 451] {
        assert_eq!(classify(&resp(s)).unwrap_err().health(), None, "{s}");
    }
    assert_eq!(Outcome::Net(NetError::TooLarge).health(), None);
    assert_eq!(
        Outcome::Net(NetError::Timeout).health(),
        None,
        "a slow answer is not an outage"
    );
    assert_eq!(Outcome::Unexpected.health(), None);
    assert_eq!(
        Outcome::ServerError.health(),
        Some(UpstreamStatus::ServerError)
    );
    assert_eq!(
        Outcome::Net(NetError::Unreachable).health(),
        Some(UpstreamStatus::Unreachable)
    );
}

#[tokio::test]
async fn a_redirect_and_a_huge_reply_say_nothing_about_health() {
    let fake = Fake::start().await;
    let get = build("github.get_repo", &json!({"repo": "acme/web"})).unwrap();
    for _ in 0..3 {
        fake.push(301, &[("location", "/elsewhere")], "");
        let e = gh(&fake).execute(&mat(), &get).await.unwrap_err();
        assert_eq!(e.health(), None);
    }
    fake.push_bytes(200, &[], vec![b'a'; 2 * 1024 * 1024 + 1]);
    assert_eq!(
        gh(&fake).execute(&mat(), &get).await.unwrap_err().health(),
        None
    );
}

// 2: branches only, and no workflow files.
#[test]
fn create_branch_makes_branches_and_put_file_spares_workflows() {
    let branch = |r: serde_json::Value| {
        build(
            "github.create_branch",
            &json!({"repo": "a/b", "body": {"ref": r, "sha": "abc"}}),
        )
    };
    assert!(branch(json!("refs/heads/feat/x")).is_ok());
    for bad in [
        "refs/tags/v1",
        "refs/heads/",
        "refs/heads/a..b",
        "refs/heads/a b",
        "heads/x",
        "refs/heads/x.lock",
        "refs/heads//x",
    ] {
        assert_eq!(branch(json!(bad)).unwrap_err(), BuildError::BadRef, "{bad}");
    }
    assert_eq!(branch(json!(7)).unwrap_err(), BuildError::BadRef);
    let none = build(
        "github.create_branch",
        &json!({"repo": "a/b", "body": {"sha": "abc"}}),
    );
    assert_eq!(none.unwrap_err(), BuildError::BadRef);

    let put = |p: &str| {
        build(
            "github.put_file",
            &json!({"repo": "a/b", "path": p, "body": {"message": "m"}}),
        )
    };
    for bad in [
        ".github/workflows/ci.yml",
        ".GitHub/Workflows/ci.yml",
        ".github/actions/x/action.yml",
        ".github/workflows",
    ] {
        assert_eq!(put(bad).unwrap_err(), BuildError::ProtectedPath, "{bad}");
    }
    for ok in [
        ".github/CODEOWNERS",
        "docs/.github/workflows/x.yml",
        "src/lib.rs",
    ] {
        assert!(put(ok).is_ok(), "{ok}");
    }
    // Reading them is fine.
    assert!(
        build(
            "github.read_file",
            &json!({"repo": "a/b", "path": ".github/workflows/ci.yml"})
        )
        .is_ok()
    );
}

// 3: an issue is not a pull request.
#[tokio::test]
async fn issue_operations_refuse_pull_requests_and_the_reverse() {
    let fake = Fake::start().await;
    let a = gh(&fake);
    let pr = r#"{"number":5,"pull_request":{"url":"x"}}"#;
    let issue = r#"{"number":5,"title":"t"}"#;
    let body = json!({"body": "x"});
    let op = |name: &str| {
        build(
            name,
            &json!({"repo": "acme/web", "number": 5, "body": body}),
        )
        .unwrap()
    };

    for name in ["github.update_issue", "github.comment_issue"] {
        let before = fake.seen().len();
        fake.push(200, &[], pr);
        let e = a.execute(&mat(), &op(name)).await.unwrap_err();
        assert_eq!((e.code(), e.health()), ("is_pull_request", None), "{name}");
        assert_eq!(fake.seen().len(), before + 1, "no write for {name}");
        assert_eq!(fake.seen()[before].path, "/repos/acme/web/issues/5");
        fake.push(200, &[], issue);
        fake.push(200, &[], "{}");
        a.execute(&mat(), &op(name)).await.unwrap();
        assert_eq!(fake.seen().len(), before + 3, "{name}");
    }
    for (name, write_path) in [
        ("github.comment_pr", "/repos/acme/web/issues/5/comments"),
        ("github.update_pr", "/repos/acme/web/pulls/5"),
    ] {
        let before = fake.seen().len();
        fake.push(200, &[], issue);
        let e = a.execute(&mat(), &op(name)).await.unwrap_err();
        assert_eq!(e.code(), "not_pull_request", "{name}");
        assert_eq!(fake.seen().len(), before + 1);
        fake.push(200, &[], pr);
        fake.push(200, &[], "{}");
        a.execute(&mat(), &op(name)).await.unwrap();
        assert_eq!(fake.seen()[before + 2].path, write_path, "{name}");
    }
    // The check itself failing leaves the write unsent.
    let before = fake.seen().len();
    fake.push(404, &[], "{}");
    let e = a
        .execute(&mat(), &op("github.update_issue"))
        .await
        .unwrap_err();
    assert_eq!(e, Outcome::NotFound);
    assert_eq!(fake.seen().len(), before + 1);
}

// 4: a credential goes to the REST API only.
#[tokio::test]
async fn a_bearer_is_refused_for_the_device_flow_host() {
    let fake = Fake::start().await;
    let req = Req::form(Host::Web, "/login/device/code", &[("client_id", "x")]);
    let e = fake.transport().send(&req, Some(TOKEN)).await.unwrap_err();
    assert_eq!(e, NetError::BadRequest);
    assert!(fake.seen().is_empty());
}

// 5: a pull request's head is a branch of this repository.
#[test]
fn a_pull_request_head_is_a_branch_of_this_repository() {
    let pr =
        |b: serde_json::Value| build("github.create_pr", &json!({"repo": "acme/web", "body": b}));
    assert!(pr(json!({"title": "t", "head": "feature", "base": "main"})).is_ok());
    assert!(pr(json!({"title": "t", "head": "acme:feature", "base": "main"})).is_ok());
    assert!(pr(json!({"title": "t", "head": "ACME:feature", "base": "main"})).is_ok());
    for bad in [
        json!({"head": "evil:feature"}),
        json!({"head": "evil:acme:feature"}),
        json!({"head": "acme:a:b"}),
        json!({"head": "a b"}),
        json!({"head": ""}),
        json!({"head": 3}),
        json!({"base": "main"}),
    ] {
        assert_eq!(pr(bad.clone()).unwrap_err(), BuildError::BadHead, "{bad}");
    }
    for extra in [
        json!({"head": "feature", "head_repo": "evil/web"}),
        json!({"head": "acme:feature", "head_repo": "acme/web"}),
    ] {
        assert_eq!(pr(extra).unwrap_err(), BuildError::UnknownField);
    }
}

// Delta review 1: a body carries only the fields its operation names.
#[test]
fn a_body_carries_only_the_fields_its_operation_names() {
    let pr =
        |b: serde_json::Value| build("github.create_pr", &json!({"repo": "acme/web", "body": b}));
    // `issue` would turn an existing issue into a pull request.
    let e = pr(json!({"issue": 42, "head": "feature", "base": "main"})).unwrap_err();
    assert_eq!(e, BuildError::UnknownField);
    let all = json!({"title": "t", "head": "feature", "base": "main", "body": "b", "draft": true, "maintainer_can_modify": false});
    assert!(pr(all).is_ok());
    // Every operation that sends a body refuses a field it does not list.
    for op in crate::connections::github::ops::OPS
        .iter()
        .filter(|o| o.method != crate::connections::github::http::Method::Get)
    {
        let input = json!({"repo": "acme/web", "number": 5, "path": "a.txt", "body": {"zzz": 1, "ref": "refs/heads/x", "head": "x"}});
        assert_eq!(
            build(op.name, &input).unwrap_err(),
            BuildError::UnknownField,
            "{}",
            op.name
        );
    }
    for (op, field) in [
        ("github.update_issue", "pull_request"),
        ("github.comment_issue", "labels"),
        ("github.update_pr", "head"),
        ("github.put_file", "committer"),
        ("github.create_branch", "force"),
    ] {
        let input = json!({"repo": "acme/web", "number": 5, "path": "a.txt", "body": {field: 1}});
        assert_eq!(
            build(op, &input).unwrap_err(),
            BuildError::UnknownField,
            "{op}"
        );
    }
    let ok = json!({"repo": "acme/web", "number": 5, "body": {"state": "closed", "title": "t"}});
    assert!(build("github.update_issue", &ok).is_ok());
}

// Delta review 3: the registry's descriptors and the built-in table cannot drift apart.
#[test]
fn every_builtin_kind_is_in_the_builtin_table_with_the_same_shapes() {
    let reg = crate::connections::adapter::Registry::builtin();
    for d in reg.descriptors() {
        let t = crate::connections::adapter::builtin_descriptor(d.kind)
            .unwrap_or_else(|| panic!("{} is not in builtin_descriptor", d.kind));
        assert_eq!(t.token_shapes, d.token_shapes, "{}", d.kind);
        assert_eq!(t.refresh_prefixes, d.refresh_prefixes, "{}", d.kind);
    }
}

// 7: a finished flow makes no more requests.
const START: &str = r#"{"device_code":"dev-code-xyz-31337","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#;

#[tokio::test]
async fn a_finished_flow_polls_no_more_and_a_bad_client_id_is_refused() {
    let fake = Fake::start().await;
    let t = fake.transport();
    let t0 = Instant::now();
    for (reply, expect_closed_after) in [
        (r#"{"access_token":"gho_testtoken0000"}"#, true),
        (r#"{"error":"expired_token"}"#, true),
        (r#"{"error":"access_denied"}"#, true),
        (r#"{"error":"incorrect_device_code"}"#, true),
        (r#"{"error":"authorization_pending"}"#, false),
    ] {
        fake.push(200, &[], START);
        let (_, mut p) = device::start(&t, "cid", t0).await.unwrap();
        fake.push(200, &[], reply);
        let at = |n| t0 + Duration::from_secs(n);
        let _ = p.poll(&t, "cid", at(5)).await;
        let before = fake.seen().len();
        // A bad client id never reaches GitHub.
        assert!(matches!(
            p.poll(&t, "a b", at(20)).await,
            Step::Failed(DeviceError::NotConfigured) | Step::Closed
        ));
        assert_eq!(fake.seen().len(), before);
        if !expect_closed_after {
            fake.push(200, &[], r#"{"error":"authorization_pending"}"#);
        }
        let again = p.poll(&t, "cid", at(30)).await;
        if expect_closed_after {
            assert!(matches!(again, Step::Closed), "{reply}");
            assert_eq!(fake.seen().len(), before, "{reply}");
        } else {
            assert!(matches!(again, Step::Wait { .. }));
        }
    }
}
