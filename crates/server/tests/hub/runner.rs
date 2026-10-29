//! The real runner (`ainkrad_runner::v2`) against the real hub (E1-11.3): pairing pins the
//! Core, the pinned runner connects (over loopback and over TLS, where the exporter is the
//! session's on both ends) and runs the no-op, and a second Core is refused before the runner
//! signs anything for it (handshake spec §17 test 27).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::gov::{self, Decider, NewPairing};
use ainkrad_proto::redact::Redactor;
use ainkrad_runner::v2::client::{Client, LinkError};
use ainkrad_runner::v2::dial::connect_once;
use ainkrad_runner::v2::key::{Enrolment, Key, State};
use ainkrad_runner::v2::pair::{Credential, pair};
use ainkrad_runner::v2::{ExecConfig, ExecDriver};

use super::proof::tls_core;
use super::{Core, quick};

pub(super) fn state(name: &str) -> State {
    let dir = std::env::temp_dir().join(format!("runner-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    State(dir)
}

/// Pairs a runner with `core` through `/pair/claim`, approving with the SAS it showed.
pub(super) async fn paired(
    core: &Core,
    base: &str,
    tls: Option<Arc<rustls::ClientConfig>>,
    st: &State,
) -> Enrolment {
    let scopes = ["runner".to_owned()];
    let new = NewPairing {
        kind: "runner",
        name: "vm",
        scopes: &scopes,
        created_by: None,
        bootstrap: false,
        recovery: false,
    };
    let now =
        ainkrad_core_server::scheduler::Clock::unix(&ainkrad_core_server::scheduler::SystemClock);
    let created = gov::create_pairing(&core.app.pool, &new, AuditActor::System, now)
        .await
        .unwrap();
    let client = Client::new(base, tls).unwrap();
    let shown: Arc<Mutex<Option<String>>> = Arc::default();
    let approver = {
        let (pool, id, shown) = (
            core.app.pool.clone(),
            created.id.clone(),
            Arc::clone(&shown),
        );
        async move {
            let sas = loop {
                if let Some(sas) = shown.lock().unwrap().clone() {
                    break sas;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            // The Core computed the same SAS on its side; approving with it proves both match.
            let stored = gov::get_pairing(&pool, &id)
                .await
                .unwrap()
                .unwrap()
                .sas
                .unwrap();
            assert_eq!(stored, sas);
            let by = Decider {
                actor: AuditActor::System,
                device: None,
                scopes: None,
            };
            gov::approve_pairing(&pool, &id, &sas, None, by, now)
                .await
                .unwrap();
        }
    };
    let show = |sas: &str| *shown.lock().unwrap() = Some(sas.to_owned());
    let pairing = pair(
        &client,
        st,
        Credential::Code(created.code.to_lowercase()),
        show,
        Duration::from_millis(50),
    );
    let (enrolment, ()) = tokio::join!(pairing, approver);
    let e = enrolment.expect("paired");
    assert_eq!(e.core_fp, core.app.auth.identity.fp, "the Core is pinned");
    let d = gov::get_device(&core.app.pool, &e.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (d.kind.as_str(), d.status.as_str(), d.scopes.as_slice()),
        ("runner", "active", &scopes[..])
    );
    e
}

pub(super) fn driver() -> Arc<ExecDriver> {
    Arc::new(ExecDriver::new(ExecConfig::default(), Redactor::new()))
}

/// Connects with `st`'s enrolment in a task; returns once the hub has it online.
async fn connected(
    core: &Core,
    base: &str,
    tls: Option<Arc<rustls::ClientConfig>>,
    st: &State,
) -> tokio::task::JoinHandle<Result<(), LinkError>> {
    let key = Arc::new(Key::load(&st.key()).unwrap());
    let enrolment = Enrolment::load(&st.enrolment()).unwrap();
    let id = enrolment.device_id.clone();
    let client = Client::new(base, tls.clone()).unwrap();
    let task = tokio::spawn(async move {
        let e = Arc::new(Mutex::new(enrolment));
        connect_once(&client, key, e, None, driver(), tls).await
    });
    for _ in 0..200 {
        if core.app.hub.online(&id) {
            return task;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the runner did not come online: {:?}", task.await);
}

#[tokio::test]
async fn a_paired_runner_connects_and_runs_the_noop_over_loopback() {
    let core = Core::start("real", quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("real");
    let e = paired(&core, &base, None, &st).await;
    let task = connected(&core, &base, None, &st).await;
    core.app
        .hub
        .noop(&e.device_id)
        .await
        .expect("the no-op ran on the real runner");
    core.app.closing.send_replace(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    let _ = std::fs::remove_dir_all(&st.0);
}

#[tokio::test]
async fn over_tls_the_real_runner_binds_its_proof_to_the_session() {
    let t = tls_core("real-tls").await;
    let base = format!("https://{}", t.core.host);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(t.root.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = Some(Arc::new(config));
    let st = state("real-tls");
    let e = paired(&t.core, &base, tls.clone(), &st).await;
    let _task = connected(&t.core, &base, tls, &st).await;
    t.core
        .app
        .hub
        .noop(&e.device_id)
        .await
        .expect("the no-op ran over TLS");
    let _ = std::fs::remove_dir_all(&st.0);
}

#[tokio::test]
async fn a_second_core_is_refused_before_anything_is_signed_for_it() {
    let a = Core::start("pin-a", quick()).await;
    let b = Core::start("pin-b", quick()).await;
    let st = state("pin");
    paired(&a, &format!("http://{}", a.host), None, &st).await;
    // The same enrolment pointed at another Core (a moved DNS name, a wrong URL).
    let key = Arc::new(Key::load(&st.key()).unwrap());
    let enrolment = Arc::new(Mutex::new(Enrolment::load(&st.enrolment()).unwrap()));
    let client = Client::new(&format!("http://{}", b.host), None).unwrap();
    let err = connect_once(&client, key, enrolment, None, driver(), None)
        .await
        .unwrap_err();
    assert!(err.mismatch(), "{err}");
    let text = err.to_string();
    assert!(text.contains("core_identity_mismatch"), "{text}");
    assert!(
        text.contains(&a.app.auth.identity.fp) && text.contains(&b.app.auth.identity.fp),
        "both fingerprints: {text}"
    );
    // B saw no signed request: none failed against it, and nothing was audited there.
    let fails: i64 = sqlx::query_scalar("SELECT count(*) FROM core_auth_limits")
        .fetch_one(&b.app.pool)
        .await
        .unwrap();
    assert_eq!(fails, 0, "no credentials reached the second Core");
    let _ = std::fs::remove_dir_all(&st.0);
}
