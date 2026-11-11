//! N24: secret kinds (file, env bundle), descriptions, groups and use counters.

use axum::http::{Method, StatusCode};
use base64::Engine;
use serde_json::{Value, json};

use super::secrets::{V1, broker, call, code, lease, redeem};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test]
async fn a_file_secret_travels_in_base64_with_its_name_and_mode() {
    let (fx, vm) = broker().await;
    let bytes = b"{\"k\": \"throwaway\"}\n\x00\xff";
    let made = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/secrets",
        json!({"name": "svc.json", "value": b64(bytes), "kind": "file", "file_name": "svc.json",
               "file_mode": "0400", "description": "a service file", "runners": [vm.id]}),
    )
    .await;
    assert_eq!(made.0, StatusCode::OK, "{}", made.1);
    assert_eq!(made.1["kind"], "file");
    assert_eq!(made.1["size"], bytes.len(), "the decoded length");
    assert_eq!(made.1["file_mode"], "0400");
    assert_eq!(made.1["description"], "a service file");
    let l = lease(&fx, "svc.json", &vm.id, None).await;
    let got = redeem(&fx, &vm, &l.1).await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    assert_eq!(got.1["kind"], "file");
    assert_eq!(got.1["file_name"], "svc.json");
    assert_eq!(got.1["file_mode"], "0400");
    let back = base64::engine::general_purpose::STANDARD
        .decode(got.1["value"].as_str().unwrap())
        .unwrap();
    assert_eq!(back, bytes);
    // The use counters moved at the redemption.
    let listed = fx.ok("/api/v1/secrets").await;
    assert_eq!(listed[0]["use_count"], 1);
    assert!(listed[0]["last_used_at"].is_string(), "{listed}");
}

#[tokio::test]
async fn a_file_secret_is_at_most_one_mebibyte_and_needs_a_clean_name() {
    let (fx, _vm) = broker().await;
    let post = |name: &str, value: String, extra: Value| {
        let mut body = json!({"name": name, "value": value, "kind": "file"});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let fx = &fx;
        async move { call(fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await }
    };
    let ok = post(
        "big",
        b64(&vec![7u8; 1024 * 1024]),
        json!({"file_name": "big.bin"}),
    )
    .await;
    assert_eq!(
        ok.0,
        StatusCode::OK,
        "1 MiB fits through the gate: {}",
        ok.1
    );
    let over = post(
        "bigger",
        b64(&vec![7u8; 1024 * 1024 + 1]),
        json!({"file_name": "a"}),
    )
    .await;
    assert_eq!(code(&over), (StatusCode::BAD_REQUEST, "too_large"));
    for name in ["", "../x", "a/b", ".."] {
        let r = post("f", b64(b"x"), json!({"file_name": name})).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{name:?}: {}", r.1);
    }
    let no_name = post("f", b64(b"x"), json!({})).await;
    assert_eq!(no_name.0, StatusCode::BAD_REQUEST, "{}", no_name.1);
    let bad_mode = post(
        "f",
        b64(b"x"),
        json!({"file_name": "a", "file_mode": "0200"}),
    )
    .await;
    assert_eq!(bad_mode.0, StatusCode::BAD_REQUEST, "{}", bad_mode.1);
    let not_b64 = post("f", "***".to_owned(), json!({"file_name": "a"})).await;
    assert_eq!(not_b64.0, StatusCode::BAD_REQUEST, "{}", not_b64.1);
}

#[tokio::test]
async fn an_env_bundle_is_checked_line_by_line() {
    let (fx, vm) = broker().await;
    let mk = |v: &str| {
        let body = json!({"name": "dotenv", "value": v, "kind": "env_bundle"});
        let fx = &fx;
        async move { call(fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await }
    };
    for bad in ["no equals", "lower=1", "PATH=/x", "# only a comment\n"] {
        assert_eq!(mk(bad).await.0, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    let ok = mk("# c\nA=1\nB=\"two\"\n\nC_3='x y'").await;
    assert_eq!(
        (ok.0, &ok.1["kind"]),
        (StatusCode::OK, &json!("env_bundle")),
        "{}",
        ok.1
    );
    let _ = vm;
}

#[tokio::test]
async fn a_group_gives_its_runners_to_members_and_lends_them_all() {
    let (fx, vm) = broker().await;
    let other = super::secrets::runner(&fx, "other").await;
    let g = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/secret-groups",
        json!({"name": "aws", "description": "AWS production", "runners": [vm.id]}),
    )
    .await;
    assert_eq!(g.0, StatusCode::OK, "{}", g.1);
    assert_eq!(
        code(
            &call(
                &fx,
                &fx.dev,
                Method::POST,
                "/api/v1/secret-groups",
                json!({"name": "aws"})
            )
            .await
        ),
        (StatusCode::CONFLICT, "conflict")
    );
    for (n, extra) in [
        ("aws.key", json!({})),
        ("aws.secret", json!({})),
        ("aws.own", json!({"runners": [other.id]})),
    ] {
        let mut body = json!({"name": n, "value": V1, "group": "aws"});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let r = call(&fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await;
        assert_eq!(r.0, StatusCode::OK, "{}", r.1);
        assert_eq!(r.1["group"], "aws");
    }
    let listed = fx.ok("/api/v1/secrets").await;
    let by = |n: &str| {
        listed
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == n)
            .unwrap()
            .clone()
    };
    assert_eq!(
        by("aws.key")["effective_runners"],
        json!([vm.id]),
        "inherited"
    );
    assert_eq!(by("aws.key")["runners"], json!([]));
    assert_eq!(
        by("aws.own")["effective_runners"],
        json!([other.id]),
        "its own wins"
    );
    // A single lease works through the inherited scope.
    assert_eq!(lease(&fx, "aws.key", &vm.id, None).await.0, StatusCode::OK);
    assert_eq!(
        lease(&fx, "aws.own", &vm.id, None).await.0,
        StatusCode::BAD_REQUEST
    );

    let lent = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/secret-groups/aws/leases",
        json!({"runner": vm.id}),
    )
    .await;
    assert_eq!(lent.0, StatusCode::OK, "{}", lent.1);
    let names: Vec<_> = lent.1["leases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["secret"].clone())
        .collect();
    assert_eq!(
        names,
        [json!("aws.key"), json!("aws.secret")],
        "not the member that is another's"
    );
    for l in lent.1["leases"].as_array().unwrap() {
        let got = redeem(&fx, &vm, &json!({"lease": l["lease"]})).await;
        assert_eq!(
            (got.0, &got.1["value"]),
            (StatusCode::OK, &json!(V1)),
            "{}",
            got.1
        );
    }
    let groups = fx.ok("/api/v1/secret-groups").await;
    assert_eq!(
        groups[0]["members"],
        json!(["aws.key", "aws.own", "aws.secret"])
    );

    // One level: a group is not a member of anything; a group with secrets cannot be deleted.
    let del = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        "/api/v1/secret-groups/aws",
        Value::Null,
    )
    .await;
    assert_eq!(code(&del), (StatusCode::CONFLICT, "conflict"));
    let up = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/secret-groups/aws",
        json!({"description": "changed", "runners": [vm.id, other.id]}),
    )
    .await;
    assert_eq!(up.1["description"], "changed", "{}", up.1);
    // A secret may leave its group, and then the empty group goes.
    for n in ["aws.key", "aws.own", "aws.secret"] {
        let r = call(
            &fx,
            &fx.dev,
            Method::PUT,
            &format!("/api/v1/secrets/{n}"),
            json!({"value": V1, "group": ""}),
        )
        .await;
        assert!(r.1["group"].is_null(), "{}", r.1);
    }
    let del = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        "/api/v1/secret-groups/aws",
        Value::Null,
    )
    .await;
    assert_eq!(del.0, StatusCode::OK, "{}", del.1);
    let no_group = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/secrets",
        json!({"name": "x", "value": V1, "group": "nope"}),
    )
    .await;
    assert_eq!(no_group.0, StatusCode::BAD_REQUEST, "{}", no_group.1);
}
