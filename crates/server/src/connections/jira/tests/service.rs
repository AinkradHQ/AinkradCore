//! Ainkrad's sign-in service (N23): the Core holds no client secret, so the exchange and the
//! refresh go to the service, signed with the Core identity key (`AINKRAD-SVC-V1`).

use std::sync::atomic::Ordering;

use super::*;
use crate::auth::crypto::{b64, fingerprint, sha256, unb64, verify};
use crate::connections::jira::{CallError, FlowError};
use crate::store::connections::secret;

const TOKEN: &str = "POST /v1/jira/token";
const REFRESH_EP: &str = "POST /v1/jira/refresh";

/// What the service checks, in the contract's words: header formats, fingerprint = SHA-256(SPKI),
/// the signature over the 8-field string with the exact body hash.
fn assert_signed(s: &Seen) {
    let h = |k: &str| {
        s.headers
            .get(k)
            .unwrap_or_else(|| panic!("no {k} header"))
            .clone()
    };
    let spki = unb64(&h("ainkrad-key"), 122).expect("key is 91 bytes base64url");
    let fp = h("ainkrad-core");
    assert_eq!(fp.len(), 43);
    assert_eq!(fp, fingerprint(&spki), "fingerprint is SHA-256 of the SPKI");
    assert_eq!(h("ainkrad-alg"), "ES256");
    assert_eq!(h("content-type"), "application/json");
    let ts = h("ainkrad-timestamp");
    assert_eq!(ts, unix_secs(NOW).unwrap().to_string());
    let nonce = h("ainkrad-nonce");
    assert_eq!(unb64(&nonce, 22).map(|n| n.len()), Some(16));
    let msg = [
        "AINKRAD-SVC-V1",
        &fp,
        "ES256",
        "POST",
        &s.path,
        &ts,
        &nonce,
        &b64(&sha256(&s.raw)),
    ]
    .join("\n");
    let sig = unb64(&h("ainkrad-signature"), 86).expect("signature is 64 bytes base64url");
    assert!(
        verify(&spki, msg.as_bytes(), &sig),
        "the signature verifies"
    );
    assert!(s.query.is_empty() && s.auth.is_none());
}

fn tokens(f: &Fx) {
    f.fake.reply(
        "POST /v1/jira/token",
        200,
        json!({"access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 3600,
            "scope": "read:jira-work offline_access", "token_type": "Bearer"}),
    );
}

async fn finish(f: &Fx) -> Result<crate::connections::jira::Finished, FlowError> {
    let s = f.jira.start(1, REDIRECT, None).unwrap();
    f.jira.finish(1, &s.state, "dummy-code", None, NOW).await
}

#[tokio::test]
async fn the_exchange_goes_to_the_service_signed_and_with_no_secret() {
    let f = fx_hosted().await;
    tokens(&f);
    let s = f.jira.start(1, REDIRECT, None).unwrap();
    assert!(
        s.authorize_url
            .contains(crate::connections::jira::BUILT_IN_CLIENT_ID)
    );
    let fin = f
        .jira
        .finish(1, &s.state, "dummy-code", None, NOW)
        .await
        .unwrap();
    assert_eq!(fin.sites.len(), 1);
    assert_eq!(
        f.fake.count("POST /oauth/token"),
        0,
        "nothing goes to Atlassian directly"
    );
    let seen = f.fake.last(TOKEN).unwrap();
    assert_signed(&seen);
    assert_eq!(seen.body["code"], "dummy-code");
    assert_eq!(seen.body["redirect_uri"], REDIRECT);
    assert_eq!(seen.body["code_verifier"].as_str().unwrap().len(), 64);
    assert!(seen.body.get("client_secret").is_none() && seen.body.get("client_id").is_none());
    // A new nonce every time.
    let n1 = seen.headers["ainkrad-nonce"].clone();
    finish(&f).await.unwrap();
    assert_ne!(f.fake.last(TOKEN).unwrap().headers["ainkrad-nonce"], n1);
}

#[tokio::test]
async fn the_refresh_goes_to_the_service_and_the_rotated_token_is_sealed() {
    let f = fx_hosted().await;
    let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let k = n.clone();
    f.fake.on(REFRESH_EP, move |s| {
        assert_signed(s);
        assert_eq!(s.body, json!({"refresh_token": REFRESH}));
        k.fetch_add(1, Ordering::SeqCst);
        Reply::json(
            200,
            json!({"access_token": "acc2-7f3a9d41e0b2",
            "refresh_token": "ref2-91c4d2b7a6e1", "expires_in": 3600}),
        )
    });
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 30))
        .await;
    let m = f.jira.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some("ref2-91c4d2b7a6e1"));
    assert_eq!(n.load(Ordering::SeqCst), 1);
    assert_eq!(f.fake.count("POST /oauth/token"), 0);
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(stored.refresh(), Some("ref2-91c4d2b7a6e1"));
}

#[tokio::test]
async fn a_dead_grant_is_an_auth_failure_and_service_faults_are_plain_messages() {
    let f = fx_hosted().await;
    let err = json!({"error": {"code": "invalid_grant", "message": "x"}});
    f.fake.reply(TOKEN, 400, err);
    let e = finish(&f).await.unwrap_err();
    assert!(
        matches!(e, FlowError::Exchange(CallError::AuthFailed)),
        "{e:?}"
    );
    for (status, code, said) in [
        (401, "stale_timestamp", "clock"),
        (502, "service_misconfigured", "no working Atlassian app"),
        (502, "upstream_unreachable", "could not reach Atlassian"),
        (429, "rate_limited", "busy"),
        (500, "internal", "had an error"),
        (400, "bad_request", "refused"),
    ] {
        f.fake.reply(
            TOKEN,
            status,
            json!({"error": {"code": code, "message": "m"}}),
        );
        let e = finish(&f).await.unwrap_err();
        let text = e.to_string();
        assert!(
            text.contains("sign-in service") || text.contains("clock"),
            "{text}"
        );
        assert!(text.contains(said), "{code}: {text}");
        assert!(matches!(e, FlowError::Exchange(CallError::SignIn(_))));
    }
}

#[tokio::test]
async fn a_service_that_is_down_says_so() {
    let f = fx_hosted().await;
    // Nothing listens at this address.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = l.local_addr().unwrap();
    drop(l);
    let jira = Jira::loopback(OAuthApp::hosted(&[REDIRECT]), dead);
    jira.set_signer(std::sync::Arc::new(crate::auth::Identity::ephemeral()));
    let s = jira.start(1, REDIRECT, None).unwrap();
    let e = jira
        .finish(1, &s.state, "dummy-code", None, NOW)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("could not be reached"), "{e}");
    drop(f);
}

#[tokio::test]
async fn an_admins_own_secret_keeps_the_direct_exchange() {
    let f = fx(true).await;
    f.fake.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 3600}),
    );
    finish(&f).await.unwrap();
    assert_eq!(f.fake.count(TOKEN), 0, "the service is not called");
    let sent = f.fake.last("POST /oauth/token").unwrap().body;
    assert_eq!(sent["client_secret"], CLIENT_SECRET);
}

#[test]
fn the_config_picks_the_path() {
    use crate::connections::jira::OAuthApp;
    let own = OAuthApp::new("id", "secret", &[REDIRECT]).unwrap();
    let hosted = OAuthApp::hosted(&[REDIRECT]).unwrap();
    assert!(!own.same(&hosted), "switching between the two is a change");
    assert!(format!("{hosted:?}").contains("redacted"));
}

// ----- GitHub App installation tokens through the service (S1) -----

mod github_app {
    use std::sync::Arc;

    use super::*;
    use crate::connections::github::install::InstallError;
    use crate::connections::github::{Github, Transport};
    use crate::connections::jira::http::Http;
    use crate::store::connections::NewConnection;

    const PATH: &str = "POST /v1/github/installation-token";
    const USER_TOKEN: &str = "gho_dummyusertoken0001";

    fn github(f: &Fx) -> Github {
        let g = Github::with_service(Arc::new(Transport::strict()), Http::loopback(f.addr));
        g.installer()
            .set_signer(Arc::new(crate::auth::Identity::ephemeral()));
        g
    }

    async fn signed_in(f: &Fx) {
        signed_in_until(f, None).await
    }

    async fn signed_in_until(f: &Fx, expires: Option<&str>) {
        let who = Who {
            workspace: 1,
            by_device: "d_test",
            actor: AuditActor::System,
            now: NOW,
        };
        let new = NewConnection {
            kind: "github",
            name: "me",
            label: "GitHub",
            auth_method: "oauth",
        };
        let m = Material::new(USER_TOKEN, None, expires).unwrap();
        create(&f.pool, &f.sealer, &Registry::builtin(), &new, &m, who)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_service_mints_after_a_signed_call_with_the_users_token() {
        let f = fx_hosted().await;
        signed_in(&f).await;
        f.fake.reply(
            PATH,
            200,
            json!({"token": "ghs_installtoken0000", "expires_at": "2026-11-06T12:00:00Z",
                "account": "acme", "repositories": ["acme/api"]}),
        );
        let (m, account) = github(&f)
            .mint_hosted(&f.pool, &f.sealer, 1, 4242, NOW)
            .await
            .unwrap();
        assert_eq!(m.access(), "ghs_installtoken0000");
        assert_eq!(m.expires_at.as_deref(), Some("2026-11-06T12:00:00.000Z"));
        assert_eq!(account.as_deref(), Some("acme"));
        let seen = f.fake.last(PATH).unwrap();
        assert_signed(&seen);
        assert_eq!(
            seen.body,
            json!({"installation_id": 4242, "user_token": USER_TOKEN})
        );
    }

    #[tokio::test]
    async fn an_install_that_is_not_theirs_is_refused_plainly() {
        let f = fx_hosted().await;
        signed_in(&f).await;
        f.fake.reply(
            PATH,
            403,
            json!({"error": {"code": "not_your_installation", "message": "m"}}),
        );
        let e = github(&f)
            .mint_hosted(&f.pool, &f.sealer, 1, 7, NOW)
            .await
            .unwrap_err();
        assert!(matches!(e, InstallError::NotYours), "{e:?}");
        assert_eq!(e.code(), "installation_not_yours");
    }

    #[tokio::test]
    async fn a_dead_or_expired_user_token_means_sign_in_again() {
        let f = fx_hosted().await;
        signed_in(&f).await;
        f.fake.reply(
            PATH,
            401,
            json!({"error": {"code": "bad_user_token", "message": "m"}}),
        );
        let e = github(&f)
            .mint_hosted(&f.pool, &f.sealer, 1, 7, NOW)
            .await
            .unwrap_err();
        assert!(matches!(e, InstallError::NoUserToken), "{e:?}");
    }

    #[tokio::test]
    async fn an_expired_user_token_is_not_sent() {
        let f = fx_hosted().await;
        signed_in_until(&f, Some(&at(-10))).await;
        let e = github(&f)
            .mint_hosted(&f.pool, &f.sealer, 1, 7, NOW)
            .await
            .unwrap_err();
        assert!(matches!(e, InstallError::NoUserToken), "{e:?}");
        assert_eq!(f.fake.count(PATH), 0);
    }

    #[tokio::test]
    async fn without_a_github_sign_in_the_service_is_not_asked() {
        let f = fx_hosted().await;
        let e = github(&f)
            .mint_hosted(&f.pool, &f.sealer, 1, 7, NOW)
            .await
            .unwrap_err();
        assert!(matches!(e, InstallError::NoUserToken), "{e:?}");
        assert_eq!(f.fake.count(PATH), 0);
    }

    #[tokio::test]
    async fn a_service_that_is_down_or_faulty_is_a_plain_error() {
        let f = fx_hosted().await;
        signed_in(&f).await;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = l.local_addr().unwrap();
        drop(l);
        let g = Github::with_service(Arc::new(Transport::strict()), Http::loopback(dead));
        g.installer()
            .set_signer(Arc::new(crate::auth::Identity::ephemeral()));
        let e = g
            .mint_hosted(&f.pool, &f.sealer, 1, 7, NOW)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, InstallError::Service(w) if w.contains("could not be reached")),
            "{e:?}"
        );
        f.fake.reply(
            PATH,
            502,
            json!({"error": {"code": "service_misconfigured", "message": "m"}}),
        );
        let e = github(&f)
            .mint_hosted(&f.pool, &f.sealer, 1, 7, NOW)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, InstallError::Service(w) if w.contains("no working")),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn an_admins_own_key_keeps_the_local_path() {
        let f = fx_hosted().await;
        let out = std::process::Command::new("openssl")
            .args(["genrsa", "2048"])
            .output()
            .unwrap();
        let key = crate::connections::github::app::AppKey::new(
            "123",
            &String::from_utf8(out.stdout).unwrap(),
        )
        .unwrap();
        let g = github(&f);
        g.installer().set_key(Some(key));
        assert!(g.installer().has_own_key());
        // `mint_for` takes the local path when a key is set (the signed JWT, unchanged tests in
        // `github/tests/app_cases.rs`); the service is not what mints.
        assert_eq!(f.fake.count(PATH), 0);
    }
}
