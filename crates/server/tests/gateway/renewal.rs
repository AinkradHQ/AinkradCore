//! Renewal on an accelerated clock (E1-06.3): 90 days pass in about two seconds. The renewal
//! fires two thirds in (not before), the new certificate is swapped in place, a TLS
//! connection held across the swap keeps serving, and a new connection gets the new
//! certificate.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use ainkrad_core_server::gateway::{acme, tls::Cert};

use super::common::{Ca, Fx, get, peer_serial, tls};
use super::{Target, start};

/// 60 simulated days per 1.5 real seconds.
const SPEED: u32 = 3_456_000;

#[tokio::test]
async fn a_renewal_two_thirds_in_swaps_the_certificate_under_a_held_connection() {
    let ca = Arc::new(Ca::new());
    let fx = Fx::new("renewal").await;
    let running = start(&fx, "public", &ca).await;
    let Target::Tls(port) = running.target else {
        unreachable!()
    };
    let certs = running.certs.clone().unwrap();
    let first = certs.live().unwrap();
    let host = running.host.clone();

    let mut held = tls(&ca, port).await.unwrap();
    assert_eq!(peer_serial(&held), first.serial());
    assert_eq!(get(&mut held, "/healthz", &host, None).await.0, 200);

    let (t0, i0) = (SystemTime::now(), Instant::now());
    let now = move || t0 + i0.elapsed() * SPEED;
    let orders = Arc::new(AtomicUsize::new(0));
    let ordered_at = Arc::new(std::sync::Mutex::new(None));
    let (o, at, issuer, store) = (
        Arc::clone(&orders),
        Arc::clone(&ordered_at),
        Arc::clone(&ca),
        super::acme(&fx),
    );
    let order = move || {
        o.fetch_add(1, Ordering::SeqCst);
        at.lock().unwrap().get_or_insert(now());
        let (chain, key) = issuer.leaf(90);
        // Persisted first, as `Acme::order` does, then swapped in by `renew`.
        let cert: Result<Cert, _> = store.store_cert(&chain, &key);
        async move { cert }
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let renewing = tokio::spawn(acme::renew(
        Arc::clone(&certs),
        now,
        Duration::from_millis(10),
        order,
        async move { drop(stopped.await) },
    ));

    let deadline = Instant::now() + Duration::from_secs(10);
    while certs.live().unwrap().serial() == first.serial() {
        assert!(Instant::now() < deadline, "no renewal within 10 s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = stop.send(());
    renewing.await.unwrap();
    assert!(orders.load(Ordering::SeqCst) >= 1);
    let at = ordered_at.lock().unwrap().unwrap();
    let life = first.not_after.duration_since(first.not_before).unwrap();
    let early = first.renew_at() - life.mul_f64(0.02);
    assert!(at >= early, "renewed before two thirds of the lifetime");
    assert!(at < first.not_after, "renewed in time");

    // The held connection (opened on the old certificate) still serves.
    assert_eq!(get(&mut held, "/healthz", &host, None).await.0, 200);
    let new = certs.live().unwrap().serial();
    let fresh = tls(&ca, port).await.unwrap();
    assert_eq!(
        peer_serial(&fresh),
        new,
        "a new connection gets the new certificate"
    );
    // What was persisted is what is served: a restart serves the renewed certificate.
    let stored = super::acme(&fx).load_cert().unwrap();
    assert_eq!(stored.serial(), new);
    drop((held, fresh));
    running.stop().await;
}
