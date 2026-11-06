use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

use super::fake::Fake;
use crate::connections::github::Outcome;
use crate::connections::github::app::{AppKey, mint};

/// A throwaway key made for each test run with the `openssl` tool (ring cannot make RSA keys);
/// it signs nothing real and is never written to the repository.
fn pem() -> String {
    let out = std::process::Command::new("openssl")
        .args(["genrsa", "2048"])
        .output()
        .expect("the openssl tool makes the test key");
    assert!(out.status.success(), "openssl genrsa failed");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn a_bad_key_or_id_is_refused_and_debug_hides_it() {
    assert!(AppKey::new("123", "not a key").is_none());
    assert!(
        AppKey::new(
            "123",
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
        )
        .is_none()
    );
    assert!(AppKey::new("", &pem()).is_none());
    assert!(AppKey::new("1 2", &pem()).is_none());
    let k = AppKey::new("123", &pem()).unwrap();
    assert!(!format!("{k:?}").contains("123"));
}

#[tokio::test]
async fn mints_an_installation_token_with_a_signed_app_jwt() {
    let fake = Fake::start().await;
    let key = AppKey::new("123456", &pem()).unwrap();
    fake.push(
        201,
        &[],
        r#"{"token":"ghs_installtoken0000","expires_at":"2026-11-06T12:00:00Z"}"#,
    );
    let m = mint(&fake.transport(), &key, 4242).await.unwrap();
    assert_eq!(m.access(), "ghs_installtoken0000");
    assert_eq!(m.expires_at.as_deref(), Some("2026-11-06T12:00:00Z"));
    assert_eq!(m.refresh(), None);

    let s = &fake.seen()[0];
    assert_eq!(
        (s.method.as_str(), s.path.as_str()),
        ("POST", "/app/installations/4242/access_tokens")
    );
    let jwt = s
        .header("authorization")
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let claims = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&claims).unwrap();
    assert_eq!(v["iss"], "123456");
    assert_eq!(v["exp"].as_i64().unwrap() - v["iat"].as_i64().unwrap(), 600);
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let signed = format!("{}.{}", parts[0], parts[1]);
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_der())
        .verify(signed.as_bytes(), &sig)
        .expect("the JWT is signed with the App key");
}

#[tokio::test]
async fn a_refused_mint_is_a_plain_outcome() {
    let fake = Fake::start().await;
    let key = AppKey::new("1", &pem()).unwrap();
    fake.push(
        401,
        &[],
        r#"{"message":"A JSON web token could not be decoded"}"#,
    );
    assert_eq!(
        mint(&fake.transport(), &key, 1).await.unwrap_err(),
        Outcome::AuthFailed
    );
    fake.push(404, &[], "{}");
    assert_eq!(
        mint(&fake.transport(), &key, 1).await.unwrap_err(),
        Outcome::NotFound
    );
    fake.push(201, &[], r#"{"nope":1}"#);
    assert_eq!(
        mint(&fake.transport(), &key, 1).await.unwrap_err(),
        Outcome::Unexpected
    );
}
