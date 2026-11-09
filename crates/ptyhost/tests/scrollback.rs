//! The on-disk scrollback ring through the real `ainkrad-ptyhost` binary (E2-04.3, E2-06.2):
//! replay past the memory ring, the per-terminal bound, output only, deletion with the
//! terminal or its dead host, and the runner's request to shed. Every host is killed by
//! `TestDir`'s guard, pass or fail.

mod support;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use support::TestDir;

use ainkrad_proto::v2::Size;
use ainkrad_ptyhost::client::{HostReader, HostWriter, connect, launch, new_id, scan_report};
use ainkrad_ptyhost::host::{random_hex, scrollback_dir};
use ainkrad_ptyhost::pty::{Spec, environment};
use ainkrad_ptyhost::store;
use ainkrad_ptyhost::wire::{FromHost, ToHost};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const BIN: &str = env!("CARGO_BIN_EXE_ainkrad-ptyhost");
const SIZE: Size = Size { rows: 24, cols: 80 };

fn tmp() -> TestDir {
    let d = PathBuf::from(format!("/tmp/aps-{}", &random_hex().unwrap()[..8]));
    std::fs::create_dir_all(&d).unwrap();
    TestDir(d)
}

fn sh(script: &str, cap: Option<u64>) -> Spec {
    Spec {
        program: Some("/bin/sh".to_owned()),
        args: vec!["-c".to_owned(), script.to_owned()],
        cwd: Some("/".to_owned()),
        env: environment(
            &std::env::vars_os().collect::<Vec<_>>(),
            &[],
            &[],
            &BTreeMap::new(),
        ),
        size: SIZE,
        scrollback_bytes: cap,
    }
}

async fn start(dir: &Path, spec: &Spec) -> (String, u32, HostReader, HostWriter) {
    let id = new_id().unwrap();
    let info = launch(Path::new(BIN), dir, &id, spec).await.unwrap();
    support::register(dir, info.pid, info.child);
    let (_, r, mut w) = connect(dir, &id).await.unwrap();
    w.send(&ToHost::Attach { seq: 0 }).await.unwrap();
    (id, info.pid, r, w)
}

/// Reads frames until `until` holds of the live output; the bytes, and whether a snapshot came.
async fn read_until(r: &mut HostReader, until: impl Fn(&[u8]) -> bool) -> (Vec<u8>, bool) {
    let (mut out, mut snap) = (Vec::new(), false);
    let end = Instant::now() + Duration::from_secs(30);
    while !until(&out) {
        let left = end.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, r.recv()).await {
            Ok(Ok(Some(FromHost::Out { data, .. }))) => out.extend(STANDARD.decode(data).unwrap()),
            Ok(Ok(Some(FromHost::Snapshot { .. }))) => snap = true,
            Ok(Ok(Some(_))) => {}
            other => panic!("{other:?} after {} bytes", out.len()),
        }
    }
    (out, snap)
}

fn has(n: &'static str) -> impl Fn(&[u8]) -> bool {
    move |o| String::from_utf8_lossy(o).contains(n)
}

/// Everything in the terminal directory's scrollback, as one byte string.
fn ring_bytes(dir: &Path) -> Vec<u8> {
    let sd = scrollback_dir(dir);
    let mut all = Vec::new();
    for e in std::fs::read_dir(sd).unwrap().flatten() {
        all.extend(std::fs::read(e.path()).unwrap());
    }
    all
}

fn disk_total(dir: &Path) -> u64 {
    store::usage(&scrollback_dir(dir)).iter().map(|u| u.1).sum()
}

/// A fresh attach at `seq`: the replayed bytes and whether a snapshot came first.
async fn reattach(dir: &Path, id: &str, seq: u64, want: u64) -> (Vec<u8>, bool) {
    let (_, mut r, mut w) = connect(dir, id).await.unwrap();
    w.send(&ToHost::Attach { seq }).await.unwrap();
    let mut out = Vec::new();
    let mut snap = false;
    let end = Instant::now() + Duration::from_secs(30);
    while (out.len() as u64) < want && !snap && Instant::now() < end {
        match tokio::time::timeout(Duration::from_secs(5), r.recv()).await {
            Ok(Ok(Some(FromHost::Out { data, .. }))) => out.extend(STANDARD.decode(data).unwrap()),
            Ok(Ok(Some(FromHost::Snapshot { .. }))) => snap = true,
            Ok(Ok(Some(_))) => {}
            _ => break,
        }
    }
    (out, snap)
}

/// Output beyond the 1 MiB memory ring replays from disk, byte for byte, in bounded frames
/// (a backlog over `MAX_LINE` as one frame would loop the reattach forever); the files are
/// `0600` in a `0700` directory.
#[tokio::test]
async fn output_older_than_memory_replays_from_disk() {
    let dir = tmp();
    let n: usize = 3 << 20;
    let script = format!("head -c {n} /dev/zero | tr '\\0' a; echo END; sleep 600");
    let (id, _, mut r, _w) = start(&dir, &sh(&script, None)).await;
    read_until(&mut r, has("END")).await;
    let info = connect(&dir, &id).await.unwrap().0;
    let (bytes, snap) = reattach(&dir, &id, 0, info.seq).await;
    assert!(!snap, "the disk ring holds it: no snapshot");
    assert_eq!(bytes.len() as u64, info.seq);
    assert!(bytes[..n].iter().all(|b| *b == b'a'));
    assert!(bytes[n..].starts_with(b"END"));
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&scrollback_dir(&dir)), 0o700);
    let files: Vec<_> = std::fs::read_dir(scrollback_dir(&dir))
        .unwrap()
        .flatten()
        .collect();
    assert!(!files.is_empty());
    for f in files {
        assert_eq!(mode(&f.path()), 0o600, "{:?}", f.path());
    }
}

/// The disk use of one terminal stays within its cap, and a resume before what it holds gets a
/// snapshot, not a gap.
#[tokio::test]
async fn a_terminal_stays_within_its_cap_and_a_stale_seq_gets_a_snapshot() {
    let dir = tmp();
    let cap = store::CAP_MIN;
    let script = "head -c 2097152 /dev/zero | tr '\\0' b; echo END; sleep 600";
    let (id, _, mut r, _w) = start(&dir, &sh(script, Some(cap))).await;
    read_until(&mut r, has("END")).await;
    let info = connect(&dir, &id).await.unwrap().0;
    assert!(
        disk_total(&dir) <= cap + 64 * 1024,
        "{} > cap {cap}",
        disk_total(&dir)
    );
    let (_, snap) = reattach(&dir, &id, 0, info.seq).await;
    assert!(snap, "seq 0 is gone from memory and disk: a snapshot");
    let (tail, snap) = reattach(&dir, &id, info.seq - 10_000, 10_000).await;
    assert!(!snap && tail.len() == 10_000, "a recent seq replays");
}

/// Nothing typed is ever written: with the terminal's echo off, the typed line reaches the
/// shell and is in no ring file, while the output the shell printed is (so the check is not
/// vacuous).
#[tokio::test]
async fn typed_input_is_never_written_to_disk() {
    let dir = tmp();
    let script = "stty -echo; echo READY; read x; echo AFTER-$$; sleep 600";
    let (_, _, mut r, mut w) = start(&dir, &sh(script, None)).await;
    read_until(&mut r, has("READY")).await;
    w.send(&ToHost::Input {
        data: STANDARD.encode("TYPED-SECRET-LINE\n"),
    })
    .await
    .unwrap();
    read_until(&mut r, has("AFTER-")).await;
    let disk = ring_bytes(&dir);
    let text = String::from_utf8_lossy(&disk);
    assert!(text.contains("AFTER-"), "the output is on disk");
    assert!(!text.contains("TYPED-SECRET"), "typed input must not be");
}

/// The ring goes with its terminal: after the exit is read, and for a host killed with
/// `kill -9` once the runner's scan finds it dead; a stray old file with no host is swept too.
#[tokio::test]
async fn the_ring_is_deleted_with_the_terminal_a_dead_host_and_strays() {
    let dir = tmp();
    let (done, _, mut r, mut w) = start(&dir, &sh("echo GONE-SOON", None)).await;
    wait_exit(&mut r).await;
    w.send(&ToHost::Ack).await.unwrap();
    while let Ok(Some(_)) = r.recv().await {}
    assert!(
        store::usage(&scrollback_dir(&dir))
            .iter()
            .all(|u| u.0 != done),
        "closed: the ring is deleted"
    );

    let (dead, pid, mut r2, _w2) = start(&dir, &sh("echo ALIVE; sleep 600", None)).await;
    read_until(&mut r2, has("ALIVE")).await;
    assert!(disk_total(&dir) > 0);
    std::process::Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .unwrap();
    // The stray: ring files of a terminal that has no record, old enough to be swept.
    let stray = scrollback_dir(&dir).join("t_stray.0.ring");
    std::fs::write(&stray, b"AKRING01\0\0\0\0\0\0\0\0").unwrap();
    let old = std::time::SystemTime::now() - Duration::from_secs(3600);
    std::fs::File::options()
        .write(true)
        .open(&stray)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let report = scan_report(&dir).await;
        if report.orphaned.contains(&dead) {
            break;
        }
        assert!(Instant::now() < end, "the dead host was not found");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        store::usage(&scrollback_dir(&dir)).is_empty(),
        "a dead host's ring and a stray one are removed: {:?}",
        store::usage(&scrollback_dir(&dir))
    );
}

/// `Shed` frees disk (the runner's budget): the disk use drops, and a resume from before what
/// remains gets a snapshot while the terminal itself goes on.
#[tokio::test]
async fn shed_frees_disk_and_the_terminal_goes_on() {
    let dir = tmp();
    let script = "head -c 1500000 /dev/zero | tr '\\0' c; echo END; read x; echo MORE; sleep 600";
    let (id, _, mut r, mut w) = start(&dir, &sh(script, None)).await;
    read_until(&mut r, has("END")).await;
    let before = disk_total(&dir);
    assert!(before > 1_000_000);
    for _ in 0..2 {
        w.send(&ToHost::Shed).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(disk_total(&dir) < before / 4, "{}", disk_total(&dir));
    let info = connect(&dir, &id).await.unwrap().0;
    let (_, snap) = reattach(&dir, &id, 0, info.seq).await;
    assert!(snap, "what was shed is a snapshot now");
    w.send(&ToHost::Input {
        data: STANDARD.encode("\n"),
    })
    .await
    .unwrap();
    read_until(&mut r, has("MORE")).await;
    assert!(String::from_utf8_lossy(&ring_bytes(&dir)).contains("MORE"));
}

/// Waits for the exit frame.
async fn wait_exit(r: &mut HostReader) {
    loop {
        match tokio::time::timeout(Duration::from_secs(20), r.recv()).await {
            Ok(Ok(Some(FromHost::Exit { .. }))) => return,
            Ok(Ok(Some(_))) => {}
            other => panic!("no exit: {other:?}"),
        }
    }
}

/// One attach never queues more than the default cap, however large the terminal's own cap:
/// with a 64 MiB cap and 10 MiB printed, a resume from 0 gets a snapshot (not 10 MiB of
/// frames), and one within the last megabyte replays exactly.
#[tokio::test]
async fn a_resume_far_back_is_a_snapshot_not_a_huge_replay() {
    let dir = tmp();
    let script = "head -c 10485760 /dev/zero | tr '\\0' d; echo END; sleep 600";
    let (id, _, mut r, _w) = start(&dir, &sh(script, Some(store::CAP_MAX))).await;
    read_until(&mut r, has("END")).await;
    let info = connect(&dir, &id).await.unwrap().0;
    assert!(disk_total(&dir) > 9_000_000, "it is all on disk");
    let (bytes, snap) = reattach(&dir, &id, 0, info.seq).await;
    assert!(
        snap && bytes.is_empty(),
        "a snapshot, got {} bytes",
        bytes.len()
    );
    let (tail, snap) = reattach(&dir, &id, info.seq - (1 << 20), 1 << 20).await;
    assert!(!snap && tail.len() == 1 << 20);
}
