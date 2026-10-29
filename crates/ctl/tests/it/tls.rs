//! The public listener: TLS 1.3 with a certificate from a test CA placed where the Core keeps
//! its ACME certificate (so no ACME runs). The first device bootstraps over the admin socket;
//! the second pairs from the QR payload alone (it names the Core and its fingerprint) over
//! HTTPS, then uses it. Without the CA the certificate is refused before anything is sent.

use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

use crate::common::*;

/// A CA, and a leaf for `localhost` it signed: (CA PEM, leaf PEM, leaf key PEM).
fn test_ca() -> (String, String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = params.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    (ca_pem, leaf.pem(), leaf_key.serialize_pem())
}

#[test]
fn pair_by_qr_and_talk_over_tls() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(format!("ctl-tls-{}", std::process::id()));
    let (ca, leaf, key) = test_ca();
    let host = format!("localhost:{port}");
    let listen = s(&[
        "--listen",
        &format!("public:{port}"),
        "--hostname",
        "localhost",
        "--acme-contact",
        "ops@example.com",
    ]);
    let core = Core::start_with(
        dir.join("x"),
        dir.join("x").join("admin.sock"),
        listen,
        Some(host.clone()),
        |home| {
            std::fs::create_dir_all(home.join("tls")).unwrap();
            std::fs::write(home.join("tls").join("cert.pem"), &leaf).unwrap();
            std::fs::write(home.join("tls").join("key.pem"), &key).unwrap();
        },
    );
    let ca_file = core.dir.join("ca.pem");
    std::fs::write(&ca_file, &ca).unwrap();
    let ca_flag = s(&["--ca", &ca_file.display().to_string()]);
    let ks_a = core.keystore("mac");
    bootstrap(&core, &ks_a);
    let a = s(&["--keystore", &ks_a.display().to_string()]);

    let o = ctl(&args(&[
        &a,
        &s(&["device", "add", "laptop", "--scopes", "read"]),
    ]));
    assert!(o.status.success(), "{o:?}");
    let out = stdout(&o);
    let (pairing, qr) = (
        field(&out, "pairing_id").unwrap(),
        field(&out, "qr").unwrap(),
    );
    assert!(qr.contains(&format!("h=localhost&p={port}&")), "{qr}");

    let ks_b = core.keystore("laptop");
    let b = args(&[&s(&["--keystore", &ks_b.display().to_string()]), &ca_flag]);
    let mut claim = spawn_pair(&ca_flag, &ks_b, &qr, &[]);
    let mut lines = Lines::of(claim.stdout.take().unwrap());
    let wait = Duration::from_secs(20);
    let dev = lines
        .next(wait)
        .unwrap()
        .strip_prefix("device ")
        .unwrap()
        .to_owned();
    let sas = lines
        .next(wait)
        .unwrap()
        .strip_prefix("sas ")
        .unwrap()
        .to_owned();
    let ok = ctl(&args(&[&a, &s(&["device", "approve", &pairing, &sas])]));
    assert!(ok.status.success(), "{ok:?}");
    assert_eq!(lines.next(wait).as_deref(), Some("status active"));
    assert!(claim.wait().unwrap().success());
    record(lines.seen.clone());

    let h = ctl(&args(&[&b, &s(&["health"])]));
    assert!(h.status.success(), "{h:?}");
    let out = stdout(&h);
    assert_eq!(field(&out, "endpoint"), Some(format!("https://{host}")));
    assert!(out.contains(&dev));
    let ev = ctl(&args(&[
        &b,
        &s(&["events", "tail", "--after", "0", "--no-follow"]),
    ]));
    assert!(ev.status.success() && stdout(&ev).contains(&dev), "{ev:?}");

    // Without the CA the certificate is not trusted: TLS fails, nothing is sent.
    let untrusted = ctl(&s(&["--keystore", &ks_b.display().to_string(), "health"]));
    assert_eq!(untrusted.status.code(), Some(1), "{untrusted:?}");
    assert!(String::from_utf8_lossy(&untrusted.stderr).contains("TLS"));
    drop(core);
    let _ = std::fs::remove_dir_all(&dir);
}
