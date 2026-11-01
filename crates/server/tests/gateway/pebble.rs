//! A real ACME order against Pebble (Let's Encrypt's test CA), both challenges, and a forced
//! re-order under a held connection. Pebble is not part of `make test` (it is a Go binary or
//! a Docker image, and validation needs fixed ports), so this runs only with
//! `AINKRAD_PEBBLE=1` and is skipped, with a note on stderr, otherwise. To run it:
//!
//! ```text
//! go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest   # or the Docker image
//! PEBBLE_VA_NOSLEEP=1 pebble -config test/config/pebble-config.json   # from Pebble's source
//! AINKRAD_PEBBLE=1 AINKRAD_PEBBLE_ROOT=<pebble>/test/certs/pebble.minica.pem \
//!   cargo test -p ainkrad-core-server --test gateway pebble
//! ```
//!
//! Defaults match Pebble's shipped config: directory `https://localhost:14000/dir`,
//! management `https://localhost:15000`, validation on :5001 (TLS-ALPN-01) and :5002
//! (HTTP-01). The name is `127.0.0.1.nip.io` (public DNS, an A record only): Pebble resolves
//! `localhost` to `::1` first and the public listener binds IPv4. Override with
//! `AINKRAD_PEBBLE_{DIRECTORY,MANAGEMENT,DOMAIN,TLS_PORT,HTTP_PORT}`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_core_server::api::router;
use ainkrad_core_server::gateway::{Gateway, Limits, Listen};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use super::common::{Fx, get, peer_serial, tls_to};

fn env(name: &str, default: &str) -> String {
    std::env::var(format!("AINKRAD_PEBBLE_{name}")).unwrap_or_else(|_| default.to_owned())
}

#[tokio::test]
async fn pebble_issues_by_both_challenges_and_a_reorder_keeps_a_held_connection() {
    if std::env::var("AINKRAD_PEBBLE").as_deref() != Ok("1") {
        eprintln!(
            "skipped: set AINKRAD_PEBBLE=1 with Pebble running (see tests/gateway/pebble.rs)"
        );
        return;
    }
    // The order's progress and failures are logged.
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let minica = std::path::PathBuf::from(env("ROOT", "pebble.minica.pem"));
    let domain = env("DOMAIN", "127.0.0.1.nip.io");
    let tls_port: u16 = env("TLS_PORT", "5001").parse().unwrap();
    let http_port: u16 = env("HTTP_PORT", "5002").parse().unwrap();
    for http01 in [false, true] {
        let fx = Fx::new(&format!("pebble-{http01}")).await;
        let acme = ainkrad_core_server::gateway::acme::Acme {
            hostname: domain.clone(),
            contact: "ops@example.test".to_owned(),
            directory: env("DIRECTORY", "https://localhost:14000/dir"),
            http01,
            ca_root: Some(minica.clone()),
            dir: fx.dir.join("tls"),
            seal: std::sync::Arc::new(ainkrad_core_server::ops::secretbox::SecretBox::new(
                &[7; 32],
            )),
        };
        let listen = Listen::Public {
            port: tls_port,
            http01: http01.then_some(http_port),
            acme: acme.clone(),
        };
        let gateway = Gateway::bind(listen, Limits::default()).await.unwrap();
        let certs = gateway.certs().unwrap();
        assert!(
            certs.live().is_none(),
            "no certificate before the first order"
        );
        let host = format!("{domain}:{tls_port}");
        let app = fx.app(&host);
        let closing = Arc::clone(&app.closing);
        let served =
            tokio::spawn(gateway.serve(router(app), Arc::clone(&closing), Duration::from_secs(5)));

        // The first order runs as soon as serving starts.
        let started = Instant::now();
        while certs.live().is_none() {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "no certificate (http01 {http01})"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        eprintln!("http01={http01}: issued in {:?}", started.elapsed());
        let root = pebble_root(&minica).await;
        let mut held = tls_to(root.clone(), &domain, tls_port).await.unwrap();
        let first = peer_serial(&held);
        assert_eq!(first, certs.live().unwrap().serial());
        assert_eq!(get(&mut held, "/healthz", &host, None).await.0, 200);

        // A forced re-order, swapped in place while `held` stays open.
        let cert = acme.order(&certs).await.unwrap();
        certs.set(cert);
        let second = certs.live().unwrap().serial();
        assert_ne!(first, second);
        assert_eq!(
            get(&mut held, "/healthz", &host, None).await.0,
            200,
            "held across the swap"
        );
        let fresh = tls_to(root, &domain, tls_port).await.unwrap();
        assert_eq!(peer_serial(&fresh), second);
        assert!(
            fx.dir.join("tls/account.json").exists(),
            "the account is kept"
        );
        drop((held, fresh));
        closing.send_replace(true);
        served.await.unwrap().unwrap();
    }
}

/// Pebble's issuing root, from its management interface (it changes on every Pebble start).
async fn pebble_root(minica: &std::path::Path) -> CertificateDer<'static> {
    let pem = std::fs::read(minica).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap())
        .build()
        .unwrap();
    let url = format!("{}/roots/0", env("MANAGEMENT", "https://localhost:15000"));
    let text = client.get(url).send().await.unwrap().text().await.unwrap();
    CertificateDer::from_pem_slice(text.as_bytes()).unwrap()
}
