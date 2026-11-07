//! The connection gate's narrow lift for Linear (C8): the redactor reads `lin_api_` and
//! `lin_oauth_` tokens as `linear_token` and the descriptor declares that shape, so with
//! `secrets.connections` on ONE own token is sealed at `secrets.mode` 1, and nothing else real.
//! The two halves are tested together: with either one missing every Linear key would be refused.

use std::sync::Arc;

use super::*;
use crate::connections::linear::{DESCRIPTOR, Linear};
use crate::store::secrets::Error;

fn own(prefix: &str) -> String {
    format!("{prefix}{}", "A1b2C3d4E5".repeat(4))
}

async fn lin_fx() -> Fx {
    let mut fx = fx().await;
    fx.reg.register(Arc::new(Linear::new(None))).unwrap();
    fx
}

async fn set(fx: &Fx, key: Key, value: &str) {
    crate::store::settings::set(&fx.pool, key, Scope::Server, value, AuditActor::System, NOW)
        .await
        .unwrap();
}

async fn try_create(fx: &Fx, kind: &str, name: &str, m: &Material) -> Result<Connection, Error> {
    let new = NewConnection {
        kind,
        name,
        label: "A test connection",
        auth_method: "token",
    };
    create(&fx.pool, &fx.sealer, &fx.reg, &new, m, w(NOW)).await
}

fn one(access: &str) -> Material {
    Material::new(access, None, None).unwrap()
}

#[test]
fn the_descriptor_names_the_shape_the_redactor_really_reads() {
    let r = ainkrad_proto::redact::Redactor::new();
    assert_eq!(DESCRIPTOR.token_shapes, ["linear_token"]);
    for prefix in ["lin_api_", "lin_oauth_"] {
        let shape = DESCRIPTOR.token_shapes[0];
        assert_eq!(
            r.text(&own(prefix)),
            format!("[redacted:{shape}]"),
            "{prefix}"
        );
    }
}

#[tokio::test]
async fn off_by_default_a_real_linear_token_is_refused() {
    let fx = lin_fx().await;
    for prefix in ["lin_api_", "lin_oauth_"] {
        let r = try_create(&fx, "linear", prefix, &one(&own(prefix))).await;
        assert_eq!(code(r), "real_secret_refused", "{prefix}");
    }
}

#[tokio::test]
async fn on_it_admits_one_own_token_and_a_sign_in_with_a_shapeless_refresh_token() {
    let fx = lin_fx().await;
    set(&fx, Key::SecretsConnections, "1").await;
    for (i, prefix) in ["lin_api_", "lin_oauth_"].into_iter().enumerate() {
        let token = own(prefix);
        let c = try_create(&fx, "linear", &format!("n{i}"), &one(&token))
            .await
            .unwrap();
        let (back, _) = secret::open(&fx.pool, &fx.sealer, 1, c.id).await.unwrap();
        assert_eq!(back.access(), token, "{prefix}");
    }
    let signed = Material::new(&own("lin_oauth_"), Some("refresh-3b9f6e2d1a70"), None).unwrap();
    let c = try_create(&fx, "linear", "signed", &signed).await.unwrap();
    // A rotation obeys the same gate.
    secret::replace(&fx.pool, &fx.sealer, c.id, &one(&own("lin_api_")), w(NOW))
        .await
        .unwrap();
}

#[tokio::test]
async fn on_it_still_refuses_anything_that_is_not_one_own_token() {
    let fx = lin_fx().await;
    set(&fx, Key::SecretsConnections, "1").await;
    let (a, b) = (own("lin_api_"), own("lin_oauth_"));
    let blobs = [
        // Another service's shape.
        one(&own("ghp_")),
        one(&own("sk-proj-")),
        // Two keys in one value, spaced, glued, or split by a line separator.
        one(&format!("{a} {b}")),
        one(&format!("{a}{b}")),
        one(&format!("{a}\u{2028}{b}")),
        // An own token as the refresh token, or a real refresh token beside an own access token.
        Material::new("shapeless-access-9d41e0b2", Some(&a), None).unwrap(),
        Material::new(&a, Some(&b), None).unwrap(),
    ];
    for (i, m) in blobs.iter().enumerate() {
        let r = try_create(&fx, "linear", &format!("x{i}"), m).await;
        assert!(r.is_err(), "blob {i} was admitted");
        assert_eq!(code(r), "real_secret_refused", "blob {i}");
    }
    // A kind that declares no such shape never admits it.
    let r = try_create(&fx, "fake", "f", &one(&a)).await;
    assert_eq!(code(r), "real_secret_refused");
}

#[tokio::test]
async fn the_lift_loosens_no_other_gate() {
    let fx = lin_fx().await;
    set(&fx, Key::SecretsConnections, "1").await;
    set(&fx, Key::SecretsMode, "0").await;
    let r = try_create(&fx, "linear", "a", &one(&own("lin_api_"))).await;
    assert_eq!(code(r), "secrets_disabled");
    // A provider account does not take a Linear token as its key.
    let single = crate::store::secrets_user::single_key(
        &ainkrad_proto::redact::Redactor::new(),
        &own("lin_api_"),
    );
    assert!(!single);
}
