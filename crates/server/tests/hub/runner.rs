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
    // A default runner (security review RH3) advertises only `noop`; `exec.run` is refused
    // in the hub and never sent.
    let live = core.app.hub.runners();
    assert_eq!(live[&e.device_id].drivers[0].commands, ["noop"]);
    let exec = ainkrad_proto::v2::Command::ExecRun(ainkrad_proto::v2::ExecRun {
        program: "/bin/true".to_owned(),
        args: vec![],
        cwd: None,
        env: Default::default(),
        env_pass: vec![],
        limits: Default::default(),
    });
    let refused = core
        .app
        .hub
        .dispatch_elevated(
            &e.device_id,
            exec,
            ainkrad_core_server::hub::Elevated::for_tests(),
        )
        .err()
        .unwrap();
    assert_eq!(
        refused.code,
        ainkrad_proto::v2::ErrorCode::UnsupportedCommand
    );
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

/// Handshake spec §13 rotation and security review RH7, end to end with the real runner: in the
/// window the Core still presents its old key and sends the statement, and the runner records
/// the new key beside its pin; once the Core has switched, the runner connects, runs the no-op
/// and moves its pin, and the old key is refused from then on.
#[tokio::test]
async fn a_rotated_core_keeps_its_runners() {
    use ainkrad_core_server::auth::Identity;
    use ainkrad_core_server::gateway::Listen;
    use ainkrad_core_server::scheduler::{Clock, SystemClock};
    let dir = std::env::temp_dir().join(format!("core-hub-rotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let now = SystemClock.unix();
    let old = Identity::load_at(&dir, now).unwrap();
    let r = Identity::rotate(&dir, now).unwrap();
    let tcp = || Listen::Tcp("127.0.0.1:0".to_owned());
    let a = Core::start_on("rotate-a", quick(), tcp(), Some(&dir), None).await;
    assert_eq!(
        a.app.auth.identity.fp, old.fp,
        "the old key signs in the window"
    );
    assert_eq!(a.app.auth.identity.rotation.as_ref(), Some(&r));
    let st = state("rotate");
    let base_a = format!("http://{}", a.host);
    let e = paired(&a, &base_a, None, &st).await;
    let key = Arc::new(Key::load(&st.key()).unwrap());
    let enrolment = Arc::new(Mutex::new(Enrolment::load(&st.enrolment()).unwrap()));
    let connect = |base: &str, save: Option<std::path::PathBuf>| {
        let client = Client::new(base, None).unwrap();
        let (key, enrolment) = (Arc::clone(&key), Arc::clone(&enrolment));
        tokio::spawn(
            async move { connect_once(&client, key, enrolment, save, driver(), None).await },
        )
    };
    let first = connect(&base_a, Some(st.enrolment()));
    for _ in 0..250 {
        if enrolment.lock().unwrap().next_fp.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let announced = enrolment.lock().unwrap().clone();
    assert_eq!(announced.core_fp, old.fp, "the pin stays in the window");
    assert_eq!(announced.next_fp.as_deref(), Some(r.new_fp.as_str()));
    assert_eq!(
        Enrolment::load(&st.enrolment()).unwrap(),
        announced,
        "saved"
    );
    first.abort();

    // The window is over: the next start of the Core is the new key.
    Identity::load_at(&dir, r.not_before).unwrap();
    let b = Core::start_on("rotate-b", quick(), tcp(), Some(&dir), None).await;
    assert_eq!(b.app.auth.identity.fp, r.new_fp);
    assert!(b.app.auth.identity.rotation.is_none());
    let _second = connect(&format!("http://{}", b.host), Some(st.enrolment()));
    for _ in 0..250 {
        if b.app.hub.online(&e.device_id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    b.app
        .hub
        .noop(&e.device_id)
        .await
        .expect("the no-op ran on the new key");
    let moved = enrolment.lock().unwrap().clone();
    assert_eq!(
        (moved.core_fp.as_str(), moved.next_fp.as_deref()),
        (r.new_fp.as_str(), None)
    );
    assert_eq!(Enrolment::load(&st.enrolment()).unwrap(), moved, "saved");

    // The old key (still held by the first Core) is no longer accepted.
    let client = Client::new(&base_a, None).unwrap();
    let err = connect_once(
        &client,
        Arc::clone(&key),
        Arc::clone(&enrolment),
        None,
        driver(),
        None,
    )
    .await
    .unwrap_err();
    assert!(err.mismatch(), "{err}");
    let _ = std::fs::remove_dir_all(&st.0);
}
