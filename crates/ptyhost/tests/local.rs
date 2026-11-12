//! The local socket end to end: the real `ainkrad-ptyhost` binary, a Core key and a device key
//! made here, and the grant rules (spec `Specs/2026-11-12-local-terminal-path.md`): no grant, no
//! attach; single use; expiry; the right terminal and runner; the device's proof; the lease;
//! and that the socket is as private as the runner's.

mod support;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use support::TestDir;

use ainkrad_proto::v2::Size;
use ainkrad_proto::v2::local::{GRANT_VERSION, LocalGrant, attach_message, grant_message};
use ainkrad_ptyhost::client::{HostWriter, connect, launch, new_id};
use ainkrad_ptyhost::host::{HostConfig, local_socket_path, random_hex, run, socket_path};
use ainkrad_ptyhost::pty::{Spec, environment};
use ainkrad_ptyhost::screen::Raw;
use ainkrad_ptyhost::wire::{FromHost, ToHost, read_line};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const BIN: &str = env!("CARGO_BIN_EXE_ainkrad-ptyhost");
const RUNNER: &str = "d_runner";
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

struct Key(EcdsaKeyPair, Vec<u8>);
impl Key {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let p8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, p8.as_ref(), &rng).unwrap();
        let spki = [SPKI_PREFIX.as_slice(), pair.public_key().as_ref()].concat();
        Self(pair, spki)
    }
    fn sign(&self, m: &[u8]) -> String {
        let s = self.0.sign(&SystemRandom::new(), m).unwrap();
        URL_SAFE_NO_PAD.encode(s.as_ref())
    }
    fn spki(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.1)
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// What a Core issues, with knobs for each way a grant can be wrong.
struct Issue<'a> {
    core: &'a Key,
    device: &'a Key,
    terminal: &'a str,
    runner: &'a str,
    nonce: &'a str,
    exp: i64,
    lease: u64,
}
impl Issue<'_> {
    fn grant(&self) -> String {
        let g = LocalGrant {
            v: GRANT_VERSION,
            terminal: self.terminal.into(),
            runner: self.runner.into(),
            device: "d_app".into(),
            device_spki: self.device.spki(),
            nonce: self.nonce.into(),
            iat: now(),
            exp: self.exp,
            lease: self.lease,
        };
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&g).unwrap());
        format!("{p}.{}", self.core.sign(&grant_message(&p)))
    }
}

struct Local {
    r: BufReader<tokio::net::unix::OwnedReadHalf>,
    w: tokio::net::unix::OwnedWriteHalf,
    buf: Vec<u8>,
    challenge: String,
}
impl Local {
    async fn open(dir: &Path, id: &str) -> Self {
        let s = UnixStream::connect(local_socket_path(dir, id))
            .await
            .unwrap();
        let (r, w) = s.into_split();
        let mut l = Self {
            r: BufReader::new(r),
            w,
            buf: Vec::new(),
            challenge: String::new(),
        };
        let Some(FromHost::Challenge { nonce }) = l.next().await else {
            panic!("no challenge")
        };
        l.challenge = nonce;
        l
    }
    async fn next(&mut self) -> Option<FromHost> {
        let line = tokio::time::timeout(
            Duration::from_secs(20),
            read_line(&mut self.r, &mut self.buf),
        )
        .await
        .expect("the host answers")
        .ok()??;
        Some(serde_json::from_str(&line).unwrap())
    }
    async fn send(&mut self, m: &ToHost) {
        let mut line = serde_json::to_vec(m).unwrap();
        line.push(b'\n');
        let _ = self.w.write_all(&line).await;
    }
    /// Presents `grant`, proved by `device` over the current challenge.
    async fn auth(&mut self, grant: &str, device: &Key) {
        let sig = device.sign(&attach_message(&self.challenge, grant));
        self.send(&ToHost::Auth {
            grant: grant.to_owned(),
            sig,
        })
        .await;
    }
    /// The answer to an `Auth`: `Ok` after `Authed` and `Hello`, or the refusal text.
    async fn answer(&mut self) -> Result<u64, String> {
        match self.next().await {
            Some(FromHost::Authed {
                lease_ms,
                challenge,
            }) => {
                self.challenge = challenge;
                assert!(matches!(self.next().await, Some(FromHost::Hello { .. })));
                Ok(lease_ms)
            }
            Some(FromHost::Error { message }) => {
                // Refused: the host hangs up after the error.
                assert!(self.next().await.is_none(), "still open after a refusal");
                Err(message)
            }
            other => panic!("{other:?}"),
        }
    }
    /// Output until `needle` shows.
    async fn until(&mut self, needle: &str) {
        let mut seen = Vec::new();
        while !String::from_utf8_lossy(&seen).contains(needle) {
            match self.next().await {
                Some(FromHost::Out { data, .. }) => seen.extend(STANDARD.decode(data).unwrap()),
                Some(_) => {}
                None => panic!(
                    "closed before {needle}: {:?}",
                    String::from_utf8_lossy(&seen)
                ),
            }
        }
    }
}

fn tmp() -> TestDir {
    let d = PathBuf::from(format!("/tmp/apl-{}", &random_hex().unwrap()[..8]));
    std::fs::create_dir_all(&d).unwrap();
    TestDir(d)
}

fn cat_spec() -> Spec {
    Spec {
        program: Some("/bin/sh".to_owned()),
        args: vec![
            "-c".into(),
            "echo up; while IFS= read -r l; do echo \"got:$l\"; done".into(),
        ],
        cwd: Some("/".to_owned()),
        env: environment(
            &std::env::vars_os().collect::<Vec<_>>(),
            &[],
            &[],
            &BTreeMap::new(),
        ),
        size: Size { rows: 24, cols: 80 },
        scrollback_bytes: None,
    }
}

/// A host the runner trusts `core` on; returns the id and the runner's own connection.
async fn host(dir: &Path, core: Option<&Key>) -> (String, HostWriter) {
    let id = new_id().unwrap();
    let info = launch(Path::new(BIN), dir, &id, &cat_spec()).await.unwrap();
    support::register(dir, info.pid, info.child);
    let (_, _r, mut w) = connect(dir, &id).await.unwrap();
    if let Some(core) = core {
        w.send(&ToHost::Trust {
            core_spki: core.spki(),
            runner: RUNNER.to_owned(),
        })
        .await
        .unwrap();
    }
    // The reader is dropped, but the writer keeps the connection; the trust is applied in order.
    std::mem::forget(_r);
    (id, w)
}

fn issue<'a>(core: &'a Key, device: &'a Key, id: &'a str, nonce: &'a str) -> Issue<'a> {
    Issue {
        core,
        device,
        terminal: id,
        runner: RUNNER,
        nonce,
        exp: now() + 60,
        lease: 45,
    }
}

#[tokio::test]
async fn a_good_grant_attaches_and_types_locally() {
    let (dir, core, dev) = (tmp(), Key::new(), Key::new());
    let (id, _runner) = host(&dir, Some(&core)).await;
    let mut l = Local::open(&dir, &id).await;
    l.auth(&issue(&core, &dev, &id, "n1").grant(), &dev).await;
    assert_eq!(l.answer().await, Ok(45_000));
    l.send(&ToHost::Attach { seq: 0 }).await;
    l.until("up").await;
    l.send(&ToHost::Input {
        data: STANDARD.encode("hello\n"),
    })
    .await;
    l.until("got:hello").await;
    l.send(&ToHost::Resize {
        size: Size {
            rows: 30,
            cols: 100,
        },
    })
    .await;
    // Close, signal and ack are not a local viewer's: refused, the connection stays.
    for m in [
        ToHost::Close { grace_ms: 50 },
        ToHost::Signal {
            signal: "KILL".into(),
        },
        ToHost::Ack,
        ToHost::Shed,
        ToHost::Trust {
            core_spki: dev.spki(),
            runner: RUNNER.into(),
        },
    ] {
        l.send(&m).await;
        assert!(
            matches!(l.next().await, Some(FromHost::Error { .. })),
            "{m:?}"
        );
    }
    l.send(&ToHost::Input {
        data: STANDARD.encode("still\n"),
    })
    .await;
    l.until("got:still").await;
}

#[tokio::test]
async fn no_grant_no_attach() {
    let (dir, core, dev) = (tmp(), Key::new(), Key::new());
    let (id, _runner) = host(&dir, Some(&core)).await;
    // Typing before authenticating: refused and hung up, and nothing reaches the shell.
    let mut l = Local::open(&dir, &id).await;
    l.send(&ToHost::Attach { seq: 0 }).await;
    assert!(matches!(l.next().await, Some(FromHost::Error { .. })));
    assert!(l.next().await.is_none());
    // A connection that never speaks is dropped after the auth window.
    let mut idle = Local::open(&dir, &id).await;
    assert!(idle.next().await.is_none());
    // A host the runner has not told which Core to trust refuses every grant.
    let (id2, _r2) = host(&dir, None).await;
    let mut l = Local::open(&dir, &id2).await;
    l.auth(&issue(&core, &dev, &id2, "n2").grant(), &dev).await;
    assert!(l.answer().await.unwrap_err().contains("trust"));
}

#[tokio::test]
async fn a_forged_wrong_or_expired_grant_is_refused() {
    let (dir, core, dev) = (tmp(), Key::new(), Key::new());
    let (id, _runner) = host(&dir, Some(&core)).await;
    let other_core = Key::new();
    let cases: Vec<(String, &str)> = vec![
        (issue(&other_core, &dev, &id, "f1").grant(), "not signed"),
        (
            issue(&core, &dev, "t_someoneelse", "f2").grant(),
            "another terminal",
        ),
        (
            Issue {
                runner: "d_other",
                ..issue(&core, &dev, &id, "f3")
            }
            .grant(),
            "another runner",
        ),
        (
            Issue {
                exp: now() - 3600,
                ..issue(&core, &dev, &id, "f4")
            }
            .grant(),
            "expired",
        ),
        ("not.agrant".to_owned(), "malformed"),
    ];
    for (grant, why) in cases {
        let mut l = Local::open(&dir, &id).await;
        l.auth(&grant, &dev).await;
        let got = l.answer().await.unwrap_err();
        assert!(got.contains(why), "{got} for {why}");
    }
    // A stolen grant is no use without the device key it names.
    let thief = Key::new();
    let mut l = Local::open(&dir, &id).await;
    l.auth(&issue(&core, &dev, &id, "f5").grant(), &thief).await;
    assert!(l.answer().await.unwrap_err().contains("proof"));
    // ... and that failure did not burn the grant for its rightful holder.
    let mut l = Local::open(&dir, &id).await;
    l.auth(&issue(&core, &dev, &id, "f5").grant(), &dev).await;
    assert!(l.answer().await.is_ok());
}

#[tokio::test]
async fn a_grant_works_once() {
    let (dir, core, dev) = (tmp(), Key::new(), Key::new());
    let (id, _runner) = host(&dir, Some(&core)).await;
    let grant = issue(&core, &dev, &id, "once").grant();
    let mut a = Local::open(&dir, &id).await;
    a.auth(&grant, &dev).await;
    assert!(a.answer().await.is_ok());
    let mut b = Local::open(&dir, &id).await;
    b.auth(&grant, &dev).await;
    assert!(b.answer().await.unwrap_err().contains("already used"));
}

#[tokio::test]
async fn the_lease_ends_the_connection_unless_renewed() {
    let (dir, core, dev) = (tmp(), Key::new(), Key::new());
    let (id, _runner) = host(&dir, Some(&core)).await;
    let short = |nonce| {
        Issue {
            lease: 2,
            ..issue(&core, &dev, &id, nonce)
        }
        .grant()
    };
    // Renewed with a fresh grant before it ends: still open well past the first lease.
    let mut a = Local::open(&dir, &id).await;
    a.auth(&short("l1"), &dev).await;
    assert_eq!(a.answer().await, Ok(2000));
    a.send(&ToHost::Attach { seq: 0 }).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    a.auth(&short("l2"), &dev).await;
    loop {
        match a.next().await {
            Some(FromHost::Authed { challenge, .. }) => {
                a.challenge = challenge;
                break;
            }
            Some(_) => {}
            None => panic!("closed instead of renewed"),
        }
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    a.send(&ToHost::Input {
        data: STANDARD.encode("alive\n"),
    })
    .await;
    a.until("got:alive").await;
    // Not renewed: closed within the lease and a tick.
    let mut b = Local::open(&dir, &id).await;
    b.auth(&short("l3"), &dev).await;
    assert!(b.answer().await.is_ok());
    let started = std::time::Instant::now();
    while b.next().await.is_some() {}
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // A renewal by another device's key is refused.
    let mut c = Local::open(&dir, &id).await;
    c.auth(&short("l4"), &dev).await;
    assert!(c.answer().await.is_ok());
    let other = Key::new();
    let g = Issue {
        device: &other,
        ..issue(&core, &other, &id, "l5")
    }
    .grant();
    c.auth(&g, &other).await;
    let mut refused = false;
    while let Some(m) = c.next().await {
        refused |= matches!(m, FromHost::Error { .. });
    }
    assert!(refused);
}

#[tokio::test]
async fn the_local_socket_is_as_private_as_the_runners() {
    let dir = tmp();
    let (id, _runner) = host(&dir, None).await;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&local_socket_path(&dir, &id)), 0o600);
    assert_eq!(mode(&socket_path(&dir, &id)), 0o600);
    assert_eq!(mode(&dir), 0o700);
}

/// Another uid gets nothing on the local socket either: not even the challenge.
#[tokio::test]
async fn another_uid_is_refused_on_the_local_socket() {
    let dir = tmp().0.join("t");
    let id = new_id().unwrap();
    let mut cfg = HostConfig::new(dir.clone(), id.clone());
    cfg.allow_uid = ainkrad_sys::getuid().wrapping_add(1);
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(run(cfg, cat_spec(), Box::new(Raw::new(4096)), move |_| {
        let _ = tx.send(());
    }));
    rx.await.unwrap();
    let s = UnixStream::connect(local_socket_path(&dir, &id))
        .await
        .unwrap();
    let (r, _w) = s.into_split();
    let (mut r, mut buf) = (BufReader::new(r), Vec::new());
    assert!(matches!(
        read_line(&mut r, &mut buf).await,
        Ok(None) | Err(_)
    ));
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

/// What the local path buys: keystroke to echo over the host's socket, no network in it. Through
/// a Core 180 ms away the same round trip is at least two of those (App -> Core -> runner and
/// back), so about 360 ms; here it is the shell's own latency. The bound is loose so a loaded
/// machine does not flake; the printed median is the number.
#[tokio::test]
async fn a_keystroke_echoes_in_milliseconds_not_a_round_trip_to_the_core() {
    let (dir, core, dev) = (tmp(), Key::new(), Key::new());
    let (id, _runner) = host(&dir, Some(&core)).await;
    let mut l = Local::open(&dir, &id).await;
    l.auth(&issue(&core, &dev, &id, "lat").grant(), &dev).await;
    l.answer().await.unwrap();
    l.send(&ToHost::Attach { seq: 0 }).await;
    l.until("up").await;
    let mut times = Vec::new();
    for i in 0..40 {
        let t = std::time::Instant::now();
        l.send(&ToHost::Input {
            data: STANDARD.encode(format!("k{i}\n")),
        })
        .await;
        l.until(&format!("got:k{i}")).await;
        times.push(t.elapsed());
    }
    times.sort();
    let median = times[times.len() / 2];
    eprintln!(
        "local echo: median {median:?}, worst {:?}",
        times[times.len() - 1]
    );
    assert!(median < Duration::from_millis(100), "{median:?}");
}
