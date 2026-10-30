//! Handshake spec §17.25 with a real second OS user (KAN-251): a peer on `admin.sock` running as
//! another uid cannot claim a bootstrap pairing, through the real `peer_cred` path rather than an
//! injected `Local`. It needs root (to run the peer as `nobody`), so it is `#[ignore]`d: run
//! `scripts/peer-uid-test.sh`, which builds as you and runs only this test under `sudo`.
//!
//! The socket is 0600, so another uid is normally refused at `connect` by the file mode alone;
//! this test opens the mode to 0666 to reach the check behind it (the same-uid peer
//! credential), which is what stands if the mode is ever wrong (review I2).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::gateway::{Gateway, Limits, Listen};
use ainkrad_core_server::scheduler::SystemClock;
use ainkrad_core_server::store::{self, gov};

fn uid_of(user: &str) -> (u32, u32) {
    let id = |flag: &str| {
        let o = std::process::Command::new("id")
            .args([flag, user])
            .output()
            .unwrap();
        String::from_utf8(o.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
    };
    (id("-u"), id("-g"))
}

/// The test's private directory, removed on drop, so a panic cleans up too (review L1). It is
/// `PEER_UID_DIR` when the script made one (`mktemp -d`, which also covers a kill), else a new
/// `/tmp/pu-<random>` made by `create_dir`, which refuses any existing path, a planted symlink
/// included. `/tmp`, not `$TMPDIR`: macOS caps a socket path at 104 bytes.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = match std::env::var_os("PEER_UID_DIR") {
            Some(d) => std::path::PathBuf::from(d),
            None => {
                let d = std::path::PathBuf::from(format!(
                    "/tmp/pu-{}",
                    ainkrad_core_server::auth::crypto::random_id("x_").trim_start_matches("x_")
                ));
                std::fs::create_dir(&d).unwrap();
                d
            }
        };
        let s = Self(dir);
        let meta = std::fs::symlink_metadata(&s.0).unwrap();
        assert!(meta.is_dir(), "{} is a real directory", s.0.display());
        s
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `curl` over the socket as `uid`/`gid`: the status code and the body.
fn claim_as(uid: u32, gid: u32, sock: &str, host: &str, body: &str) -> (String, String) {
    let o = std::process::Command::new("curl")
        .uid(uid)
        .gid(gid)
        .args([
            "-s",
            "-w",
            "\n%{http_code}",
            "--unix-socket",
            sock,
            "-H",
            &format!("Host: {host}"),
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            &format!("@{body}"),
            "http://localhost/pair/claim",
        ])
        .output()
        .unwrap();
    let out = String::from_utf8(o.stdout).unwrap();
    let (body, code) = out.rsplit_once('\n').unwrap_or(("", &out));
    (code.to_owned(), body.to_owned())
}

// Multi-thread: `claim_as` blocks on `curl` while the gateway task must keep serving, which a
// single-threaded runtime cannot do (the test would hang).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root to run a peer as another uid: scripts/peer-uid-test.sh"]
async fn another_uid_on_the_admin_socket_cannot_claim_a_bootstrap_pairing() {
    let scratch = Scratch::new();
    let dir = scratch.0.clone();
    let me = std::fs::symlink_metadata(&dir).unwrap().uid();
    assert_eq!(
        me, 0,
        "run as root: scripts/peer-uid-test.sh (this test must not pass by skipping)"
    );
    let (nobody, nogroup) = uid_of("nobody");
    assert_ne!(nobody, me);
    // Only now, once it is known to be root's own new directory: `nobody` must reach the socket.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let pool = store::connect(&dir.join("core.db")).await.unwrap();
    let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
    let sock = dir.join("admin.sock");
    let gateway = Gateway::bind(Listen::Tcp("127.0.0.1:0".to_owned()), Limits::default())
        .await
        .unwrap()
        .with_admin_socket(&sock)
        .unwrap();
    // Beside a TCP listener the admin socket answers to the main listener's Host.
    let host = format!("127.0.0.1:{}", gateway.local_addr().unwrap().port());
    let app = App::new(pool.clone(), Arc::new(SystemClock), host.clone(), identity);
    let closing = Arc::clone(&app.closing);
    let served =
        tokio::spawn(gateway.serve(router(app.clone()), closing.clone(), Duration::from_secs(2)));
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();

    let scopes = ["admin".to_owned()];
    let p = gov::NewPairing {
        kind: "device",
        name: "first",
        scopes: &scopes,
        created_by: None,
        bootstrap: true,
        recovery: false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let created = gov::create_pairing(&pool, &p, ainkrad_core::audit::AuditActor::System, now)
        .await
        .unwrap();
    let dev = TestDevice::new(&app.auth.identity.fp, Arc::new(SystemClock));
    let body = dir.join("claim.json");
    std::fs::write(&body, dev.claim_body(Some(&created.code), None).to_string()).unwrap();
    std::fs::set_permissions(&body, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (sock_s, body_s) = (sock.display().to_string(), body.display().to_string());

    let (code, text) = claim_as(nobody, nogroup, &sock_s, &host, &body_s);
    assert_eq!(code, "401", "another uid: {text}");
    assert!(text.contains("pairing_failed"), "{text}");
    // The same claim from the socket's own uid goes through: the refusal was the uid, and the
    // foreign attempt did not spend the pairing.
    let (code, text) = claim_as(me, 0, &sock_s, &host, &body_s);
    assert_eq!(code, "202", "the same uid: {text}");

    closing.send_replace(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), served).await;
}
