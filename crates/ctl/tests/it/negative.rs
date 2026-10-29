//! What must be refused: a Core that is not the pinned one (nothing signed goes out), a
//! tampered or replayed request, a skewed clock (with the server's time as the hint), and a
//! resume point past retention (its own exit code).

use ainkrad_ctl::Error;
use ainkrad_ctl::client::Client;
use ainkrad_ctl::keystore::Keystore;
use ainkrad_ctl::net::{Endpoint, Net};
use ainkrad_ctl::proto::{Key, b64, unb64};

use crate::common::*;
use crate::fake::Fake;

const PINNED: &str = "PINNEDPINNEDPINNEDPINNEDPINNEDPINNEDPINNEDA";
const OTHER: &str = "OTHERCOREOTHERCOREOTHERCOREOTHERCOREOTHERCA";
const DEVICE: &str = "d_00000000000000000000000000";

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ctl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn keystore_for(
    dir: &std::path::Path,
    sock: &std::path::Path,
    core_fp: &str,
) -> std::path::PathBuf {
    let path = dir.join("ks").join("keystore.json");
    let ks = Keystore {
        device_id: DEVICE.into(),
        core_fp: core_fp.into(),
        endpoint: format!("unix:{}", sock.display()),
        host: None,
        key: Key::generate(),
    };
    ks.save(&path).unwrap();
    path
}

fn serves_other(method: &str, path: &str) -> (u16, String) {
    match (method, path) {
        ("GET", "/healthz") => (200, "ok".into()),
        ("GET", "/handshake") => (
            200,
            format!(
                r#"{{"server_version":"0.1.0","api_minor":4,"identity_fingerprint":"{OTHER}"}}"#
            ),
        ),
        _ => (500, "{}".into()),
    }
}

#[test]
fn another_core_identity_gets_nothing_signed() {
    let dir = scratch("pin");
    let fake = Fake::start(dir.join("f.sock"), serves_other);
    let ks = keystore_for(&dir, &fake.sock, PINNED);
    let o = ctl(&s(&["--keystore", &ks.display().to_string(), "health"]));
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("core_identity_mismatch") && err.contains(PINNED) && err.contains(OTHER),
        "{err}"
    );

    // A QR naming one Core, scanned against another: no claim goes out.
    let qr = format!(
        "ainkrad-pair:v1?h=localhost&p=443&c={PINNED}&s={}&e=9",
        b64(&[9; 16])
    );
    let new_ks = dir.join("new").join("keystore.json");
    let o = ctl(&s(&[
        "--socket",
        &fake.sock.display().to_string(),
        "--keystore",
        &new_ks.display().to_string(),
        "pair",
        &qr,
    ]));
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(!new_ks.exists());

    let seen = fake.requests();
    assert!(!seen.is_empty());
    for r in &seen {
        assert!(
            r.starts_with("get /healthz") || r.starts_with("get /handshake "),
            "only unsigned probes: {r}"
        );
        assert!(
            !r.contains("ainkrad-") && !r.contains(DEVICE),
            "nothing about the device: {r}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn another_core_identity_against_the_real_core() {
    let core = Core::start("pinreal");
    let ks = core.keystore("mac");
    let (dev, _) = bootstrap(&core, &ks);
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ks).unwrap()).unwrap();
    v["core_fp"] = OTHER.into();
    std::fs::write(&ks, serde_json::to_vec(&v).unwrap()).unwrap();
    let before = core.log().len();
    let o = ctl(&s(&["--keystore", &ks.display().to_string(), "health"]));
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(
        !core.log()[before..].contains(&dev),
        "the Core never heard of the device"
    );
}

fn refused_code(r: &ainkrad_ctl::net::Response) -> String {
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    format!("{} {}", r.status, v["code"].as_str().unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_replayed_and_skewed_requests_are_refused() {
    let core = Core::start("tamper");
    let ks = core.keystore("mac");
    bootstrap(&core, &ks);
    let net = Net::new(Endpoint::Unix(core.sock.clone()), None, None).unwrap();
    let mut c = Client::new(net.clone(), Keystore::load(&ks).unwrap());
    let sid = c.session().await.unwrap().id;
    let me = "/api/v1/me";

    // Signed for one path, sent to another.
    let h = c.sign("GET", me, "", Some(&sid), &[]);
    let r = net
        .send("GET", "/api/v1/events/latest", &h, Vec::new())
        .await
        .unwrap();
    assert_eq!(refused_code(&r), "401 auth_failed");
    // One body byte changed after signing.
    let push = "/api/v1/push-token";
    let h = c.sign("PUT", push, "", Some(&sid), br#"{"token":"ab"}"#);
    let r = net
        .send("PUT", push, &h, br#"{"token":"ac"}"#.to_vec())
        .await
        .unwrap();
    assert_eq!(refused_code(&r), "401 auth_failed");
    // One signature bit flipped.
    let mut h = c.sign("GET", me, "", Some(&sid), &[]);
    let sig = h
        .iter_mut()
        .find(|(k, _)| *k == "ainkrad-signature")
        .unwrap();
    let mut raw = unb64(&sig.1).unwrap();
    raw[10] ^= 1;
    sig.1 = b64(&raw);
    let r = net.send("GET", me, &h, Vec::new()).await.unwrap();
    assert_eq!(refused_code(&r), "401 auth_failed");
    // The same signed request twice (spec §17 case 3).
    let h = c.sign("GET", me, "", Some(&sid), &[]);
    assert_eq!(
        net.send("GET", me, &h, Vec::new()).await.unwrap().status,
        200
    );
    let r = net.send("GET", me, &h, Vec::new()).await.unwrap();
    assert_eq!(refused_code(&r), "401 auth_failed");
    // Four refusals stay under the (address, device) lockout: the honest request still works.
    assert_eq!(c.call("GET", me, "", None).await.unwrap().status, 200);

    // A clock 120 s fast: refused before any lookup, with the server's time as the hint.
    c.clock_offset = 120;
    c.drop_session();
    let e = c.call("GET", me, "", None).await.unwrap_err();
    let now = ainkrad_ctl::client::unix_now();
    match &e {
        Error::Refused {
            status: 401,
            code,
            server_time: Some(t),
            ..
        } if code == "clock_skew" => {
            assert!((t - now).abs() < 5, "server_time is the server's clock");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(e.code(), 8);
    assert!(e.to_string().contains("server_time"), "{e}");
    // 50 s off is inside the 60 s window (spec §17 case 5).
    c.clock_offset = 50;
    assert_eq!(c.call("GET", me, "", None).await.unwrap().status, 200);
}

fn past_retention(method: &str, path: &str) -> (u16, String) {
    match (method, path) {
        ("GET", "/handshake") => (200, format!(r#"{{"identity_fingerprint":"{PINNED}"}}"#)),
        ("POST", "/handshake/challenge") => (200, format!(r#"{{"challenge":"{}","expires_in":60}}"#, "A".repeat(43))),
        ("POST", "/handshake/session") => (
            200,
            r#"{"session_id":"s_00000000000000000000000000","expires_at":"2099-01-01T00:00:00.000Z","scopes":["read"]}"#.into(),
        ),
        ("GET", "/api/v1/events") => (
            410,
            r#"{"code":"past_retention","message":"trimmed","error_id":"err_x","floor":42}"#.into(),
        ),
        _ => (500, "{}".into()),
    }
}

#[test]
fn a_resume_point_past_retention_exits_5_with_the_floor() {
    let dir = scratch("retention");
    let fake = Fake::start(dir.join("f.sock"), past_retention);
    let ks = keystore_for(&dir, &fake.sock, PINNED);
    let o = ctl(&s(&[
        "--keystore",
        &ks.display().to_string(),
        "events",
        "tail",
        "--after",
        "3",
    ]));
    assert_eq!(o.status.code(), Some(5), "{o:?}");
    assert!(String::from_utf8_lossy(&o.stderr).contains("up to 42"));
    assert!(
        fake.requests()
            .iter()
            .any(|r| r.starts_with("get /api/v1/events?after=3&limit=1000 "))
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Spec §4: `POST /handshake {nonce}` → `{server_version, api_minor, core_spki, core_sig}`, with
/// `core_sig` the Core key over `"AINKRAD-CORE-V1\n" + host + "\n" + nonce`; §13 has native
/// clients verify it against the pinned fingerprint on each connect.
#[tokio::test]
#[ignore = "server deviation: /handshake is GET-only with identity_fingerprint and no core_spki/core_sig (crates/server/src/api.rs router, api/v1/handshake.rs); the pin check cannot be a proof"]
async fn handshake_proves_the_core_key() {
    let core = Core::start("hsproof");
    let net = Net::new(Endpoint::Unix(core.sock.clone()), None, None).unwrap();
    let nonce = b64(&[5; 16]);
    let body = serde_json::to_vec(&serde_json::json!({"nonce": nonce})).unwrap();
    let r = net.send("POST", "/handshake", &[], body).await.unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    let spki = unb64(v["core_spki"].as_str().unwrap()).unwrap();
    let sig = unb64(v["core_sig"].as_str().unwrap()).unwrap();
    let message = format!("AINKRAD-CORE-V1\nlocalhost\n{nonce}");
    assert!(ainkrad_ctl::proto::verify(&spki, message.as_bytes(), &sig));
}

/// Spec §3 and §15.4: devices are named by random opaque `d_…` ids, never by an autoincrement
/// integer that repeats across Cores and invites enumeration.
#[test]
#[ignore = "server deviation: audit rows (and so every audit event) name a device by its integer row, entity_id 1, 2, … (crates/server/src/store/gov/devices.rs audit_device, AuditEntity.id is i64); the d_ id is only in details"]
fn audit_events_name_devices_by_their_opaque_id() {
    let core = Core::start("entity");
    let ks = core.keystore("mac");
    let (dev, _) = bootstrap(&core, &ks);
    let o = ctl(&s(&[
        "--keystore",
        &ks.display().to_string(),
        "events",
        "tail",
        "--after",
        "0",
        "--no-follow",
    ]));
    let claimed = stdout(&o)
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|e| e["payload"]["action"] == "pairing.claimed")
        .unwrap();
    assert_eq!(claimed["payload"]["entity_id"], *dev);
}
