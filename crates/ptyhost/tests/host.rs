//! The PTY host end to end (E2-02, E2-03): the real `ainkrad-ptyhost` binary, started the way
//! the runner starts it, spoken to over its socket.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ainkrad_proto::v2::Size;
use ainkrad_ptyhost::client::{HostReader, HostWriter, connect, launch, new_id, scan, scan_report};
use ainkrad_ptyhost::host::{HostConfig, random_hex, record_path, run, socket_path};
use ainkrad_ptyhost::pty::{Exit, Spec, environment};
use ainkrad_ptyhost::screen::Raw;
use ainkrad_ptyhost::wire::{FromHost, ToHost};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const BIN: &str = env!("CARGO_BIN_EXE_ainkrad-ptyhost");
const SIZE: Size = Size { rows: 24, cols: 80 };

/// A short private directory (socket paths are limited to 104 bytes on macOS).
fn tmp() -> PathBuf {
    let d = PathBuf::from(format!("/tmp/aph-{}", &random_hex().unwrap()[..8]));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn spec(program: &str, args: &[&str]) -> Spec {
    Spec {
        program: Some(program.to_owned()),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        cwd: Some("/".to_owned()),
        env: environment(
            &std::env::vars_os().collect::<Vec<_>>(),
            &[],
            &[],
            &BTreeMap::new(),
        ),
        size: SIZE,
    }
}

fn sh(script: &str) -> Spec {
    spec("/bin/sh", &["-c", script])
}

async fn start(dir: &Path, spec: &Spec) -> (String, HostReader, HostWriter) {
    let id = new_id().unwrap();
    let info = launch(Path::new(BIN), dir, &id, spec).await.unwrap();
    assert_eq!(info.id, id);
    let (_, r, mut w) = connect(dir, &id).await.unwrap();
    w.send(&ToHost::Attach { seq: 0 }).await.unwrap();
    (id, r, w)
}

/// Output until `until` holds of it (or the exit, which is returned), within 20 s.
async fn read_until(
    r: &mut HostReader,
    out: &mut Vec<u8>,
    until: impl Fn(&[u8]) -> bool,
) -> Option<Exit> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !until(out) {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, r.recv()).await {
            Ok(Ok(Some(FromHost::Out { data, .. }))) => out.extend(STANDARD.decode(data).unwrap()),
            Ok(Ok(Some(FromHost::Exit { exit }))) => return Some(exit),
            Ok(Ok(Some(_))) => {}
            other => panic!("{other:?} with {:?}", String::from_utf8_lossy(out)),
        }
    }
    None
}

fn has(needle: &str) -> impl Fn(&[u8]) -> bool + '_ {
    move |o: &[u8]| String::from_utf8_lossy(o).contains(needle)
}

/// Acks the exit and waits for the host to close and clean up.
async fn ack(dir: &Path, id: &str, r: &mut HostReader, w: &mut HostWriter) {
    w.send(&ToHost::Ack).await.unwrap();
    while let Ok(Some(_)) = r.recv().await {}
    assert!(!record_path(dir, id).exists() && !socket_path(dir, id).exists());
}

fn ps() -> String {
    let o = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,stat=,command="])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// E2-02.1: `echo` runs, its output arrives, the exit follows it, the host goes on `ack`.
#[tokio::test]
async fn echo_runs_and_its_exit_follows_its_output() {
    let dir = tmp();
    let (id, mut r, mut w) = start(&dir, &spec("/bin/echo", &["MARK-e2"])).await;
    let mut out = Vec::new();
    let exit = read_until(&mut r, &mut out, |_| false).await.unwrap();
    assert!(has("MARK-e2")(&out), "{out:?}");
    assert_eq!(
        exit,
        Exit {
            code: Some(0),
            signal: None
        }
    );
    ack(&dir, &id, &mut r, &mut w).await;
}

/// E2-02.1: a size change reaches the child (`SIGWINCH` and the new size).
#[tokio::test]
async fn a_resize_reaches_the_child() {
    let dir = tmp();
    let script = "trap 'echo WINCH; stty size' WINCH; stty size; echo READY; \
                  while :; do sleep 0.05; done";
    let (id, mut r, mut w) = start(&dir, &sh(script)).await;
    let mut out = Vec::new();
    read_until(&mut r, &mut out, has("READY")).await;
    assert!(has("24 80")(&out), "{:?}", String::from_utf8_lossy(&out));
    let size = Size {
        rows: 50,
        cols: 132,
    };
    w.send(&ToHost::Resize { size }).await.unwrap();
    read_until(&mut r, &mut out, has("50 132")).await;
    assert!(has("WINCH")(&out));
    w.send(&ToHost::Close { grace_ms: 200 }).await.unwrap();
    let exit = read_until(&mut r, &mut out, |_| false).await.unwrap();
    assert_eq!(exit.code, None, "ended by a signal: {exit:?}");
    ack(&dir, &id, &mut r, &mut w).await;
}

/// E2-02.3: a secret planted in the runner's environment never reaches the child.
#[tokio::test]
async fn a_planted_secret_is_not_in_the_child() {
    let dir = tmp();
    let mut runner: Vec<_> = std::env::vars_os().collect();
    runner.push(("AWS_SECRET".into(), "planted-e2-02".into()));
    let mut s = spec("/usr/bin/env", &[]);
    s.env = environment(&runner, &[], &["AWS_SECRET".to_owned()], &BTreeMap::new());
    let (id, mut r, mut w) = start(&dir, &s).await;
    let mut out = Vec::new();
    read_until(&mut r, &mut out, |_| false).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("TERM=xterm-256color"), "{text}");
    assert!(!text.contains("planted-e2-02"), "{text}");
    ack(&dir, &id, &mut r, &mut w).await;
}

/// E2-02.4: 10 MB of binary noise and wide characters come out byte for byte.
#[tokio::test]
async fn large_binary_output_is_exact() {
    let dir = tmp();
    let mut data = Vec::with_capacity(10 << 20);
    let mut x: u32 = 0x1234_5678;
    while data.len() < 10 << 20 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((x >> 24) as u8);
        if data.len() % 4096 == 0 {
            data.extend("界🙂é\u{301}".as_bytes());
        }
    }
    let file = dir.join("noise");
    std::fs::write(&file, &data).unwrap();
    // Raw mode: no `\n` → `\r\n`, no echo, so what the program writes is what arrives.
    let script = format!(
        "stty raw -echo; printf R; read go; cat '{}'",
        file.display()
    );
    let (id, mut r, mut w) = start(&dir, &sh(&script)).await;
    let mut out = Vec::new();
    read_until(&mut r, &mut out, has("R")).await;
    let begun = Instant::now();
    w.send(&ToHost::Input {
        data: STANDARD.encode(b"go\n"),
    })
    .await
    .unwrap();
    out.clear();
    let exit = read_until(&mut r, &mut out, |_| false).await.unwrap();
    let secs = begun.elapsed().as_secs_f64();
    eprintln!(
        "10 MiB in {secs:.2} s ({:.1} MB/s)",
        10.0 * 1.048_576 / secs
    );
    assert_eq!(exit.code, Some(0));
    assert!(out == data, "{} bytes out, {} in", out.len(), data.len());
    ack(&dir, &id, &mut r, &mut w).await;
}

/// E2-02.2: 100 open/close cycles leave no zombie, no host and no child behind.
#[tokio::test]
async fn a_hundred_open_close_cycles_leave_nothing() {
    let dir = tmp();
    for _ in 0..100 {
        let (id, mut r, mut w) = start(&dir, &spec("/bin/sleep", &["997"])).await;
        w.send(&ToHost::Close { grace_ms: 100 }).await.unwrap();
        let mut out = Vec::new();
        read_until(&mut r, &mut out, |_| false).await.unwrap();
        ack(&dir, &id, &mut r, &mut w).await;
    }
    let me = std::process::id().to_string();
    let zombie = |line: &str| {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Hosts this test launched, left unreaped. (In-process hosts of other tests hold their
        // exited children as zombies on purpose until acked: review H1.)
        f.get(1) == Some(&me.as_str())
            && f.get(2).is_some_and(|s| s.starts_with('Z'))
            && line.contains("ainkrad-ptyhos")
    };
    // Hosts of tests running alongside may be a moment from being reaped: retry briefly.
    let mut table = ps();
    for _ in 0..30 {
        if !table.lines().any(zombie) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        table = ps();
    }
    for line in table.lines() {
        assert!(!zombie(line), "zombie: {line}");
        assert!(!line.contains(&*dir.to_string_lossy()), "left over: {line}");
        assert!(!line.contains("sleep 997"), "child left over: {line}");
    }
}

/// E2-03.2/.3: the process that started five hosts is killed with `kill -9`; every host keeps
/// running, a scan re-adopts all five, stale records are cleaned, and the terminals still work.
#[tokio::test]
async fn hosts_survive_their_runner_and_are_re_adopted() {
    let dir = tmp();
    let s = serde_json::to_vec(&sh("echo UP; while read l; do echo \"got $l\"; done")).unwrap();
    std::fs::write(dir.join("spec"), s).unwrap();
    let ids: Vec<String> = (0..5).map(|_| new_id().unwrap()).collect();
    // A stand-in runner: starts the hosts, then would live on.
    let mut script = String::new();
    for id in &ids {
        script.push_str(&format!(
            "'{BIN}' serve --dir '{d}' --id {id} < '{d}/spec' > '{d}/{id}.out' & ",
            d = dir.display()
        ));
    }
    script.push_str("exec sleep 300");
    let mut runner = Command::new("/bin/sh")
        .args(["-c", &script])
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    for id in &ids {
        while !std::fs::read_to_string(dir.join(format!("{id}.out")))
            .unwrap_or_default()
            .starts_with("ready")
        {
            assert!(Instant::now() < deadline, "{id} did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    runner.kill().unwrap(); // SIGKILL
    runner.wait().unwrap();
    // A record whose host is gone.
    std::fs::write(
        record_path(&dir, "t_stale"),
        r#"{"protocol":1,"pid":1,"boot":"x","started":0}"#,
    )
    .unwrap();

    let report = scan_report(&dir).await;
    assert_eq!(report.orphaned, vec!["t_stale"]);
    let found = report.live;
    let mut want = ids.clone();
    want.sort();
    assert_eq!(found.iter().map(|i| i.id.clone()).collect::<Vec<_>>(), want);
    assert!(
        !record_path(&dir, "t_stale").exists(),
        "stale record cleaned"
    );
    for id in &ids {
        let (_, mut r, mut w) = connect(&dir, id).await.unwrap();
        w.send(&ToHost::Attach { seq: 0 }).await.unwrap();
        let mut out = Vec::new();
        read_until(&mut r, &mut out, has("UP")).await;
        w.send(&ToHost::Input {
            data: STANDARD.encode(b"ping\n"),
        })
        .await
        .unwrap();
        read_until(&mut r, &mut out, has("got ping")).await;
        w.send(&ToHost::Close { grace_ms: 100 }).await.unwrap();
        read_until(&mut r, &mut out, |_| false).await.unwrap();
        ack(&dir, id, &mut r, &mut w).await;
    }
}

/// An in-process host on `spec` with `cfg` tweaks; returns its id once it serves.
async fn in_process(dir: &Path, s: Spec, tweak: impl FnOnce(&mut HostConfig)) -> String {
    let id = new_id().unwrap();
    let mut cfg = HostConfig::new(dir.to_path_buf(), id.clone());
    tweak(&mut cfg);
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(run(cfg, s, Box::new(Raw::new(4096)), move |_| {
        let _ = tx.send(());
    }));
    rx.await.unwrap();
    id
}

/// E2-03.4: the socket is `0600` in a `0700` directory, and a peer of another uid gets
/// nothing, not even the hello.
#[tokio::test]
async fn another_uid_is_refused() {
    let dir = tmp().join("t");
    let other = ainkrad_sys::getuid().wrapping_add(1);
    let id = in_process(&dir, sh("sleep 3"), |c| c.allow_uid = other).await;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&socket_path(&dir, &id)), 0o600);
    assert_eq!(mode(&record_path(&dir, &id)), 0o600);
    let refused = connect(&dir, &id).await;
    assert!(refused.is_err(), "served another uid");
}

/// E2-03.5 and the resume rules: an unknown message is skipped, a resume inside the ring gets
/// exactly the bytes after it, and one before the ring gets a snapshot first.
#[tokio::test]
async fn resume_by_seq_and_a_snapshot_when_it_is_gone() {
    let dir = tmp();
    let id = in_process(
        &dir,
        sh("printf 0123456789abcdefghij; read x; echo done"),
        |c| c.ring = 8,
    )
    .await;
    let (_, mut r, mut w) = connect(&dir, &id).await.unwrap();
    w.send(&ToHost::Unknown).await.ok(); // serialises as {"type":"unknown"}: skipped
    w.send(&ToHost::Attach { seq: 0 }).await.unwrap();
    let mut out = Vec::new();
    // Wait for all 20 bytes to have been produced.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut snap = None;
    while out.len() < 20 && Instant::now() < deadline {
        match r.recv().await.unwrap().unwrap() {
            FromHost::Out { data, .. } => out.extend(STANDARD.decode(data).unwrap()),
            FromHost::Snapshot { seq, data } => snap = Some((seq, data)),
            _ => {}
        }
        if snap.is_some() {
            break;
        }
    }
    // Attached before the output, or cut to a snapshot: either way, now resume from 14.
    let _ = (out, snap);
    let (_, mut r2, mut w2) = connect(&dir, &id).await.unwrap();
    w2.send(&ToHost::Attach { seq: 14 }).await.unwrap();
    match r2.recv().await.unwrap().unwrap() {
        FromHost::Out { seq, data } => {
            assert_eq!(seq, 14);
            assert_eq!(STANDARD.decode(data).unwrap(), b"efghij");
        }
        other => panic!("{other:?}"),
    }
    let (_, mut r3, mut w3) = connect(&dir, &id).await.unwrap();
    w3.send(&ToHost::Attach { seq: 2 }).await.unwrap();
    match r3.recv().await.unwrap().unwrap() {
        FromHost::Snapshot { seq, .. } => assert_eq!(seq, 20),
        other => panic!("{other:?}"),
    }
    w3.send(&ToHost::Close { grace_ms: 100 }).await.unwrap();
}

fn stat(pid: u32) -> String {
    let o = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

/// Review H1: once the child exited, its pid stays a zombie (so its group id cannot be
/// recycled) until the host ends, and a signal is refused rather than sent to that group.
#[tokio::test]
async fn after_the_exit_nothing_is_signalled_and_the_group_id_stays_ours() {
    let dir = tmp();
    let id = in_process(&dir, sh("exit 3"), |_| {}).await;
    let (info, mut r, mut w) = connect(&dir, &id).await.unwrap();
    let child = info.child.unwrap();
    w.send(&ToHost::Attach { seq: 0 }).await.unwrap();
    let mut out = Vec::new();
    let exit = read_until(&mut r, &mut out, |_| false).await.unwrap();
    assert_eq!(exit.code, Some(3));
    assert!(
        stat(child).starts_with('Z'),
        "a zombie holds the pid: {:?}",
        stat(child)
    );
    w.send(&ToHost::Signal {
        signal: "KILL".to_owned(),
    })
    .await
    .unwrap();
    match r.recv().await.unwrap() {
        Some(FromHost::Error { message }) => assert!(message.contains("exited"), "{message}"),
        other => panic!("{other:?}"),
    }
    // Close after the exit signals nothing either; the ack reaps the child.
    w.send(&ToHost::Close { grace_ms: 50 }).await.unwrap();
    ack(&dir, &id, &mut r, &mut w).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !stat(child).is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(stat(child), "", "reaped once the host ended");
}

/// Review M1: a scan removes the files of a host that is provably gone (its socket refuses),
/// never of one that is only slow to answer.
#[tokio::test]
async fn a_scan_removes_only_provably_dead_hosts() {
    let dir = tmp();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = |id: &str| {
        std::fs::write(
            record_path(&dir, id),
            r#"{"protocol":1,"pid":1,"boot":"x","started":0}"#,
        )
        .unwrap();
    };
    // Slow: listens, accepts, never says hello.
    let slow = tokio::net::UnixListener::bind(socket_path(&dir, "t_slow")).unwrap();
    record("t_slow");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = slow.accept().await {
            held.push(s);
        }
    });
    // Dead: a socket file nobody listens on.
    drop(std::os::unix::net::UnixListener::bind(socket_path(&dir, "t_dead")).unwrap());
    record("t_dead");
    assert!(scan(&dir).await.is_empty());
    assert!(record_path(&dir, "t_slow").exists() && socket_path(&dir, "t_slow").exists());
    assert!(!record_path(&dir, "t_dead").exists() && !socket_path(&dir, "t_dead").exists());
}

/// Review L2: a socket in a directory others can enter is not trusted.
#[tokio::test]
async fn a_socket_in_an_open_directory_is_refused() {
    let dir = tmp();
    let id = in_process(&dir, sh("sleep 2"), |_| {}).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = connect(&dir, &id).await.err().unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(connect(&dir, &id).await.is_ok());
}
