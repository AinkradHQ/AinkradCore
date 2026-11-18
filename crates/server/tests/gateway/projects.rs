//! P6-02: the public listener splits project traffic off by SNI before any Core routing. A
//! connection for `<label>.proj.test` gets the wildcard certificate and the Host router, so no
//! Core route answers on it (whatever the path, the `Host` or a valid device signature); the
//! Core's own SNI is served as before, and its Host check refuses a project `Host`.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::api::router;
use ainkrad_core_server::gateway::{Gateway, Limits, Listen, projects, tls as gtls};

use crate::acme;
use crate::common::{Ca, Fx, get, tls, tls_to};

#[tokio::test]
async fn a_project_sni_gets_the_host_router_and_never_the_core() {
    let ca = Ca::new();
    let fx = Fx::new("projects-sni").await;
    let acme = acme(&fx);
    let (chain, key) = ca.leaf(90);
    acme.store_cert(&chain, &key).unwrap();
    let listen = Listen::Public {
        port: 0,
        http01: None,
        acme,
    };
    let gateway = Gateway::bind(listen, Limits::default()).await.unwrap();
    let port = gateway.local_addr().unwrap().port();
    let host = format!("localhost:{port}");
    let app = fx.app(&host);
    let (chain, key) = ca.leaf_for("*.proj.test", 90);
    let cert = gtls::Cert::from_pem(&chain, &key).unwrap();
    let dial = Arc::new(projects::HubDial(Arc::clone(&app.hub)));
    let hosts = projects::router(app.clone(), dial, "proj.test");
    let gateway = gateway.with_projects("proj.test", cert, hosts).unwrap();
    let closing = Arc::clone(&app.closing);
    let served =
        tokio::spawn(gateway.serve(router(app), Arc::clone(&closing), Duration::from_secs(5)));

    // The wildcard verifies for a project name; nothing the Core serves answers there.
    let mut io = tls_to(ca.der.clone(), "shop.proj.test", port)
        .await
        .unwrap();
    for path in ["/healthz", "/handshake", "/api/v1/me", "/runner/v2/connect"] {
        let (status, body) = get(&mut io, path, "shop.proj.test", Some(&fx.dev)).await;
        assert_eq!(status, 404, "{path}: {body}");
        assert!(!body.contains("api_minor"), "{path}: {body}");
    }
    // The Core's Host on a project connection is still only the router's (and not a project).
    let (status, body) = get(&mut io, "/handshake", &host, None).await;
    assert_eq!(status, 404, "{body}");
    // A reserved name is not a project host: the handshake gets the Core's certificate, which
    // does not cover it, so it fails.
    assert!(
        tls_to(ca.der.clone(), "core.proj.test", port)
            .await
            .is_err()
    );

    // The Core's own SNI: unchanged, and a project Host there is refused, not proxied.
    let mut core = tls(&ca, port).await.unwrap();
    assert_eq!(
        get(&mut core, "/healthz", &host, None).await,
        (200, "ok".into())
    );
    let (status, body) = get(&mut core, "/handshake", &host, None).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = get(&mut core, "/handshake", "shop.proj.test", None).await;
    assert_eq!(status, 403, "the Core's Host check holds");

    closing.send_replace(true);
    let served = tokio::time::timeout(Duration::from_secs(10), served).await;
    served.expect("drains in time").unwrap().unwrap();
}
