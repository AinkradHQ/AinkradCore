//! The connection gate's narrow lift (C2): with `secrets.connections` on, ONE token of the
//! kind's own declared shape may be sealed at `secrets.mode` 1, and nothing else real.

use std::sync::Arc;

use super::*;
use crate::connections::github::Github;
use crate::store::secrets::Error;

fn own(prefix: &str) -> String {
    format!("{prefix}{}", "A1b2C3d4E5".repeat(4))
}

async fn gh_fx() -> Fx {
    let mut fx = fx().await;
    fx.reg.register(Arc::new(Github::strict())).unwrap();
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

#[tokio::test]
async fn off_by_default_a_real_github_token_is_refused() {
    let fx = gh_fx().await;
    let r = try_create(&fx, "github", "a", &one(&own("ghp_"))).await;
    assert_eq!(code(r), "real_secret_refused");
}

#[tokio::test]
async fn on_it_admits_one_token_of_the_kinds_own_shape() {
    let fx = gh_fx().await;
    set(&fx, Key::SecretsConnections, "1").await;
    for (i, prefix) in ["ghp_", "gho_", "ghs_", "github_pat_"]
        .into_iter()
        .enumerate()
    {
        let token = own(prefix);
        let c = try_create(&fx, "github", &format!("n{i}"), &one(&token))
            .await
            .unwrap();
        let (back, _) = secret::open(&fx.pool, &fx.sealer, 1, c.id).await.unwrap();
        assert_eq!(back.access(), token, "{prefix}");
    }
    // A rotation obeys the same gate.
    let c = make_with(&fx, "github", "rot", SECRET).await;
    secret::replace(&fx.pool, &fx.sealer, c.id, &one(&own("gho_")), w(NOW))
        .await
        .unwrap();
}

#[tokio::test]
async fn on_it_still_refuses_anything_that_is_not_one_own_token() {
    let fx = gh_fx().await;
    set(&fx, Key::SecretsConnections, "1").await;
    let (a, b) = (own("ghp_"), own("gho_"));
    let blobs = [
        // Another kind's, or another service's, shape.
        one(&own("sk-proj-")),
        one(&format!("AKIA{}", "A0".repeat(10))),
        // Two keys in one value, spaced, glued, or split by a line separator.
        one(&format!("{a} {b}")),
        one(&format!("{a}{b}")),
        one(&format!("{a}\u{2028}{b}")),
        // An own token as the refresh token, or beside a real access token.
        Material::new(SECRET, Some(&a), None).unwrap(),
        Material::new(&a, Some(&b), None).unwrap(),
    ];
    for (i, m) in blobs.iter().enumerate() {
        let r = try_create(&fx, "github", &format!("x{i}"), m).await;
        assert!(r.is_err(), "blob {i} was admitted");
        assert_eq!(code(r), "real_secret_refused", "blob {i}");
    }
    // A kind that declares no such shape never admits it: `fake` lists its own made-up one.
    let r = try_create(&fx, "fake", "f", &one(&a)).await;
    assert_eq!(code(r), "real_secret_refused");
    let c = make(&fx, "fake", "g").await;
    let r = secret::replace(&fx.pool, &fx.sealer, c.id, &one(&a), w(NOW)).await;
    assert_eq!(code(r), "real_secret_refused");
}

#[tokio::test]
async fn the_lift_loosens_no_other_gate() {
    let fx = gh_fx().await;
    set(&fx, Key::SecretsConnections, "1").await;
    // The broker off still refuses, own token or not.
    set(&fx, Key::SecretsMode, "0").await;
    let r = try_create(&fx, "github", "a", &one(&own("ghp_"))).await;
    assert_eq!(code(r), "secrets_disabled");
    // The provider-account check does not take a GitHub token as an account key.
    let r = crate::store::secrets_user::single_key(
        &ainkrad_proto::redact::Redactor::new(),
        &own("ghp_"),
    );
    assert!(!r);
    // Shapeless throwaway values need nothing.
    set(&fx, Key::SecretsMode, "1").await;
    set(&fx, Key::SecretsConnections, "0").await;
    assert!(try_create(&fx, "github", "ok", &one(SECRET)).await.is_ok());
}
