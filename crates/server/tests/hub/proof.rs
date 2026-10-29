//! Who may connect (handshake spec §13, §14): the upgrade's signed request, a runner device
//! only, the channel-bound proof both ways, one uniform refusal, one audit row per refused
//! runner, and nothing of the proof in the log. The TLS case runs on the public listener with a
//! test CA, so the exporter really is the session's.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::auth::crypto::{b64, fingerprint, unb64, verify};
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::gateway::Listen;
use ainkrad_core_server::gateway::acme::Acme;
use ainkrad_core_server::scheduler::SystemClock;
use ainkrad_proto::v2::*;
use futures_util::StreamExt;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio_tungstenite::tungstenite::Message;

use super::{Core, Fake, Ws, exec_driver, log, quick, random32, upgrade};

async fn refused_count(core: &Core) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'runner.refused'")
        .fetch_one(&core.app.pool)
        .await
        .unwrap()
}

/// The Core's refusal: the `error` code, then the close code.
async fn refusal(ws: &mut Ws) -> (ErrorCode, u16) {
    let mut code = None;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Text(t))) => {
                let f: Frame = serde_json::from_str(&t).unwrap();
                if let Ok(Some(Body::Error(e))) = f.body() {
                    assert_eq!(
                        e.message.contains("authentication failed"),
                        e.code == ErrorCode::AuthFailed
                    );
                    code = Some(e.code);
                }
            }
            Some(Ok(Message::Close(Some(c)))) => {
                return (code.expect("an error first"), c.code.into());
            }
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn only_a_signed_runner_device_gets_the_socket() {
    let core = Core::start("who", quick()).await;
    let tcp = || async {
        Box::new(
            tokio::net::TcpStream::connect(("127.0.0.1", core.port))
                .await
                .unwrap(),
        ) as Box<dyn super::Io>
    };
    let (status, body) = upgrade(tcp().await, &core.host, None).await.err().unwrap();
    assert_eq!(status, 401);
    assert!(body.contains("\"auth_failed\""), "{body}");
    // A stranger's key: the same answer.
    let stranger = TestDevice::new(&core.app.auth.identity.fp, Arc::new(SystemClock));
    stranger.set_session(Some("s_00000000000000000000000000".to_owned()));
    let (status, other) = upgrade(tcp().await, &core.host, Some(&stranger))
        .await
        .err()
        .unwrap();
    let shape = |b: &str| b.split(",\"error_id\"").next().unwrap().to_owned();
    assert_eq!((status, shape(&other)), (401, shape(&body)), "one answer");
    // An app device is authenticated but not a runner.
    let app_dev = core.device("device", &["read", "admin"]).await;
    let (status, body) = upgrade(tcp().await, &core.host, Some(&app_dev))
        .await
        .err()
        .unwrap();
    assert_eq!(status, 403);
    assert!(body.contains("forbidden_scope"), "{body}");
    assert_eq!(refused_count(&core).await, 1, "audited once");
}

#[tokio::test]
async fn a_bad_proof_a_foreign_hello_or_an_old_major_is_refused_and_audited() {
    let core = Core::start("bad", quick()).await;
    let dev = core.runner().await;
    let fp = core.app.auth.identity.fp.clone();

    // Signed for the wrong exporter.
    let mut f = Fake::plain(&core, &dev).await;
    let auth = f.hello(&dev, vec![], &random32()).await;
    f.prove(&dev, &auth, &[7; 32], &fp).await;
    assert_eq!(
        refusal(&mut f.ws).await,
        (ErrorCode::AuthFailed, close_code::POLICY)
    );

    // Another device's key over the right message.
    let mut f = Fake::plain(&core, &dev).await;
    let auth = f.hello(&dev, vec![], &random32()).await;
    let other = TestDevice::new(&fp, Arc::new(SystemClock));
    f.prove(&other, &auth, &NO_CHANNEL_BINDING, &fp).await;
    assert_eq!(
        refusal(&mut f.ws).await,
        (ErrorCode::AuthFailed, close_code::POLICY)
    );

    // A hello naming someone else gets no `auth` at all.
    let mut f = Fake::plain(&core, &dev).await;
    let hello = RunnerHello {
        protocol: PROTOCOL_VERSION.to_owned(),
        runner_version: "t".to_owned(),
        drivers: vec![],
        os: None,
        arch: None,
        device_id: Some(other.id.clone()),
        nonce: Some(b64(&random32())),
        ..RunnerHello::default()
    };
    f.send(CONTROL_STREAM, Body::Control(Control::Hello(hello.clone())))
        .await;
    assert_eq!(
        refusal(&mut f.ws).await,
        (ErrorCode::AuthFailed, close_code::POLICY)
    );

    let mut f = Fake::plain(&core, &dev).await;
    let old = RunnerHello {
        protocol: "1.4".to_owned(),
        device_id: Some(dev.id.clone()),
        ..hello
    };
    f.send(CONTROL_STREAM, Body::Control(Control::Hello(old)))
        .await;
    assert_eq!(
        refusal(&mut f.ws).await,
        (ErrorCode::UnsupportedVersion, close_code::POLICY)
    );
    // One row per device and reason per window: the two bad proofs share one.
    assert_eq!(refused_count(&core).await, 3);
    assert!(!core.app.hub.online(&dev.id));

    // Silence after the upgrade: cut at the handshake deadline.
    let mut f = Fake::plain(&core, &dev).await;
    assert_eq!(
        refusal(&mut f.ws).await,
        (ErrorCode::AuthFailed, close_code::POLICY)
    );
}

/// A test CA and a public listener whose certificate it signed.
pub struct Tls {
    pub root: CertificateDer<'static>,
    pub core: Core,
}

pub async fn tls_core(name: &str) -> Tls {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let root = params.self_signed(&ca_key).unwrap().der().clone();
    let issuer = Issuer::new(params, ca_key);
    let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    leaf.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    let key = KeyPair::generate().unwrap();
    let cert = leaf.signed_by(&key, &issuer).unwrap();
    let dir = std::env::temp_dir().join(format!("core-hub-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let acme = Acme {
        hostname: "localhost".to_owned(),
        contact: "ops@example.test".to_owned(),
        directory: "https://127.0.0.1:1/directory".to_owned(),
        http01: false,
        ca_root: None,
        dir: dir.join("tls"),
    };
    acme.store_cert(&cert.pem(), &key.serialize_pem()).unwrap();
    let listen = Listen::Public {
        port: 0,
        http01: None,
        acme,
    };
    let core = Core::start_on(name, quick(), listen, Some(&dir), None).await;
    Tls { root, core }
}

/// A TLS connection to the Core and its exporter, as the runner computes it.
async fn tls_connect(t: &Tls) -> (Box<dyn super::Io>, [u8; 32]) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(t.root.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", t.core.port))
        .await
        .unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .unwrap();
    let mut x = [0; 32];
    tls.get_ref()
        .1
        .export_keying_material(&mut x, EXPORTER_LABEL, None)
        .unwrap();
    (Box::new(tls), x)
}

#[tokio::test]
async fn over_tls_the_proof_is_bound_to_the_session_and_nothing_of_it_is_logged() {
    let t = tls_core("tls").await;
    let core = &t.core;
    let dev = core.runner().await;
    let identity = &core.app.auth.identity;

    let (io, x) = tls_connect(&t).await;
    let ws = upgrade(io, &core.host, Some(&dev))
        .await
        .expect("upgraded over TLS");
    let mut f = Fake::new(ws);
    let nonce_r = random32();
    let auth = f
        .hello(&dev, vec![exec_driver(&[OP_NOOP], 1)], &nonce_r)
        .await;
    // The Core signed this session's exporter, which the client computed on its own.
    let core_spki = unb64(&auth.core_spki, 122).unwrap();
    assert_eq!(fingerprint(&core_spki), identity.fp);
    let sig_core = unb64(&auth.sig, 86).unwrap();
    assert!(verify(
        &core_spki,
        &core_auth_message(&x, &nonce_r, &dev.id),
        &sig_core
    ));
    f.prove(&dev, &auth, &x, &identity.fp).await;
    f.welcome().await;
    assert!(core.app.hub.online(&dev.id));
    let first = (x, auth.clone());

    // Another session: a different exporter, so the first session's proof does not hold here.
    let (io, x2) = tls_connect(&t).await;
    assert_ne!(x, x2);
    assert!(!verify(
        &core_spki,
        &core_auth_message(&x2, &nonce_r, &dev.id),
        &sig_core
    ));
    let ws = upgrade(io, &core.host, Some(&dev)).await.unwrap();
    let mut f2 = Fake::new(ws);
    let auth2 = f2.hello(&dev, vec![], &random32()).await;
    // A proof for the plain-text binding (or the old session) is refused over TLS.
    f2.prove(&dev, &auth2, &NO_CHANNEL_BINDING, &identity.fp)
        .await;
    assert_eq!(
        refusal(&mut f2.ws).await,
        (ErrorCode::AuthFailed, close_code::POLICY)
    );

    let text = String::from_utf8_lossy(&log().0.lock().unwrap()).into_owned();
    let (x, auth) = first;
    for secret in [
        b64(&x),
        b64(&x2),
        b64(&nonce_r),
        auth.nonce,
        auth.sig,
        auth2.nonce,
        auth2.sig,
    ] {
        if let Some(at) = text.find(&secret) {
            panic!("logged: {}", &text[at.saturating_sub(300)..at + 60]);
        }
    }
    assert!(text.contains("runner connected"), "the log is captured");
}

/// The committed proof vectors (`tests/vectors/runner-auth-v1.json`), for runners and SDKs:
/// fixed keys from `handshake-v1.json`, fixed exporter and nonces, the exact messages and a
/// signature by each side. `UPDATE_VECTORS=1` rewrites it.
#[test]
fn the_runner_auth_vectors_hold() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/runner-auth-v1.json"
    );
    let hs: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/handshake-v1.json")).unwrap();
    let key = |k: &str| {
        base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            hs[k].as_str().unwrap(),
        )
        .unwrap()
    };
    let core = ainkrad_core_server::auth::Identity::from_pkcs8(&key("core_pkcs8")).unwrap();
    let device_id = hs["device_id"].as_str().unwrap();
    let dev = TestDevice::from_pkcs8(
        device_id,
        &key("device_pkcs8"),
        &core.fp,
        Arc::new(SystemClock),
    );
    let bytes = |from: u8| -> Vec<u8> { (from..from + 32).collect() };
    let (x, nonce_r, nonce_c) = (bytes(0), bytes(32), bytes(64));
    let core_msg = core_auth_message(&x, &nonce_r, device_id);
    let runner_msg = runner_auth_message(&x, &nonce_c, &core.fp);
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        let v = serde_json::json!({
            "comment": "Runner connection proof vectors (handshake spec §13; protocol v2 `auth`). core_auth_message = \"AINKRAD-CORE-AUTH-V1\" || exporter || nonce_r || device_id (UTF-8); runner_auth_message = \"AINKRAD-RUNNER-AUTH-V1\" || exporter || nonce_c || core_fp (the 43-character text). The exporter is TLS export_keying_material(label \"EXPORTER-ainkrad-core-v1\", no context, 32 bytes). Bytes are base64url without padding; signatures are ES256 raw r||s and randomised: verify them, never expect to reproduce them. Keys are the throwaway TEST keys of handshake-v1.json.",
            "core_spki": b64(&core.spki),
            "core_fp": core.fp,
            "device_id": device_id,
            "device_spki": b64(&dev.spki),
            "exporter": b64(&x),
            "nonce_r": b64(&nonce_r),
            "nonce_c": b64(&nonce_c),
            "core_auth_message": b64(&core_msg),
            "runner_auth_message": b64(&runner_msg),
            "sig_core": b64(&core.sign(&core_msg)),
            "sig_runner": b64(&dev.sign(&runner_msg)),
        });
        std::fs::write(path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    }
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let get = |k: &str| {
        base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            v[k].as_str().unwrap(),
        )
        .unwrap()
    };
    assert_eq!(get("core_auth_message"), core_msg);
    assert_eq!(get("runner_auth_message"), runner_msg);
    assert_eq!(v["core_fp"], core.fp);
    assert!(verify(&core.spki, &core_msg, &get("sig_core")));
    assert!(verify(&dev.spki, &runner_msg, &get("sig_runner")));
    assert!(
        !verify(&core.spki, &runner_msg, &get("sig_core")),
        "domain separated"
    );
}
