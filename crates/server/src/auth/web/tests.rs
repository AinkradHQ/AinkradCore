use super::*;
use crate::auth::testing::authenticator::{SoftAuthenticator, UP, UV};

const HOST: &str = "core.test";

fn rp() -> Passkeys {
    Passkeys::new(HOST, false).unwrap()
}

fn registered(p: &Passkeys, a: &mut SoftAuthenticator) -> Passkey {
    let options = p.start_registration("p_x", "web", 0, 300);
    let state = p.take_registration("p_x", 1).unwrap();
    let reg: RegisterPublicKeyCredential = serde_json::from_value(a.register(&options)).unwrap();
    p.webauthn
        .finish_passkey_registration(&reg, &state)
        .unwrap()
}

fn sign_in(
    p: &Passkeys,
    a: &mut SoftAuthenticator,
    key: &Passkey,
) -> WebauthnResult<AuthenticationResult> {
    let options = p.start_signin(vec![1], "ip:a", 0).unwrap();
    let cred: PublicKeyCredential = serde_json::from_value(a.assert(&options)).unwrap();
    let (state, k) = p.take_signin(&cred, 1).expect("a live ceremony");
    assert_eq!(k, vec![1], "the ceremony's own session key");
    let keys = [DiscoverableKey::from(key)];
    p.webauthn
        .finish_discoverable_authentication(&cred, state, &keys)
}

#[test]
fn relying_party_follows_the_host() {
    let p = rp();
    assert_eq!(
        (p.rp_id.as_str(), p.origin.as_str()),
        ("core.test", "https://core.test")
    );
    let p = Passkeys::new("Core.Test:8443", false).unwrap();
    assert_eq!(p.origin, "https://core.test:8443");
    assert_eq!(
        Passkeys::new("localhost:7700", true).unwrap().origin,
        "http://localhost:7700"
    );
    for refused in ["127.0.0.1:7700", "[::1]:7700", "::1", ""] {
        assert!(Passkeys::new(refused, true).is_err(), "{refused}");
    }
    assert!(
        Passkeys::new("localhost:7700", false).is_err(),
        "localhost off loopback"
    );
}

#[test]
fn options_are_es256_only_uv_required_and_resident_preferred() {
    let o = rp().start_registration("p_x", "web", 0, 300);
    let pk = &o["publicKey"];
    assert_eq!(
        pk["pubKeyCredParams"],
        json!([{"type": "public-key", "alg": -7}])
    );
    assert_eq!(pk["authenticatorSelection"]["userVerification"], "required");
    assert_eq!(pk["authenticatorSelection"]["residentKey"], "preferred");
    assert_eq!(pk["attestation"], "none");
    assert_eq!(pk["rp"]["id"], "core.test");
}

#[test]
fn registration_round_trips_and_signs_in() {
    let p = rp();
    let mut a = SoftAuthenticator::new(HOST, "https://core.test");
    let key = registered(&p, &mut a);
    assert_eq!(
        p256_spki(&key).unwrap(),
        a.spki(),
        "the SAS key is the credential's"
    );
    assert!(p.take_registration("p_x", 1).is_none(), "single use");
    let r = sign_in(&p, &mut a, &key).unwrap();
    assert!(r.user_verified());
    assert_eq!(r.counter(), 2);
}

#[test]
fn wrong_origin_rp_or_missing_uv_fail_and_challenges_are_single_use() {
    let p = rp();
    let mut a = SoftAuthenticator::new(HOST, "https://core.test");
    let key = registered(&p, &mut a);
    a.origin = "https://evil.test".into();
    assert!(sign_in(&p, &mut a, &key).is_err(), "another origin");
    a.origin = "https://core.test".into();
    a.rp_id = "evil.test".into();
    assert!(sign_in(&p, &mut a, &key).is_err(), "another RP");
    a.rp_id = HOST.into();
    a.flags = UP;
    assert!(sign_in(&p, &mut a, &key).is_err(), "no user verification");
    a.flags = UP | UV;
    assert!(sign_in(&p, &mut a, &key).is_ok());
    let options = p.start_signin(vec![1], "ip:a", 0).unwrap();
    let cred: PublicKeyCredential = serde_json::from_value(a.assert(&options)).unwrap();
    assert!(p.take_signin(&cred, 1).is_some());
    assert!(p.take_signin(&cred, 1).is_none(), "replayed");
    let options = p.start_signin(vec![1], "ip:a", 0).unwrap();
    let cred: PublicKeyCredential = serde_json::from_value(a.assert(&options)).unwrap();
    assert!(p.take_signin(&cred, CEREMONY_SECS).is_none(), "expired");
}

#[test]
fn a_counter_that_does_not_grow_is_a_possible_clone() {
    let p = rp();
    let mut a = SoftAuthenticator::new(HOST, "https://core.test");
    let mut key = registered(&p, &mut a);
    let r = sign_in(&p, &mut a, &key).unwrap();
    key.update_credential(&r);
    a.counter = Some(1);
    assert!(matches!(
        sign_in(&p, &mut a, &key),
        Err(WebauthnError::CredentialPossibleCompromise)
    ));
    // A synced passkey reports 0 from the start and is exempt.
    let mut s = SoftAuthenticator::new(HOST, "https://core.test");
    s.counter = None;
    let key = registered(&p, &mut s);
    assert!(sign_in(&p, &mut s, &key).is_ok());
    assert!(sign_in(&p, &mut s, &key).is_ok());
}

#[test]
fn signins_are_capped_per_address_and_no_address_evicts_another() {
    let p = rp();
    let mine = p.start_signin(vec![1], "ip:a", 0).unwrap();
    for i in 0..SIGNINS_PER_ADDR * 4 {
        p.start_signin(vec![1], &format!("ip:x{}", i % 2), 0)
            .unwrap();
    }
    assert_eq!(p.signins_len(), 1 + 2 * SIGNINS_PER_ADDR);
    let mut a = SoftAuthenticator::new(HOST, "https://core.test");
    let cred: PublicKeyCredential = serde_json::from_value(a.assert(&mine)).unwrap();
    assert!(p.take_signin(&cred, 1).is_some(), "ip:a's is still live");
}

#[test]
fn step_up_ceremonies_are_bound_to_their_session() {
    let p = rp();
    let mut a = SoftAuthenticator::new(HOST, "https://core.test");
    let key = registered(&p, &mut a);
    let (c, _) = p.start_stepup("s_a", &key, 0);
    assert!(p.take_stepup("s_b", &c, 1).is_none(), "another session's");
    assert!(
        p.take_stepup("s_a", "other", 1).is_none(),
        "another challenge, and spent"
    );
    let (c, _) = p.start_stepup("s_a", &key, 0);
    assert!(p.take_stepup("s_a", &c, CEREMONY_SECS).is_none(), "expired");
}
