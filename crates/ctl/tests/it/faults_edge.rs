//! The rest of the fault suite (E1-14.4): an expired certificate on the public listener, a
//! read-only database, and a stalled events client. `make e1-exit-faults`.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, date_time_ymd};

use crate::common::*;
use crate::runner::*;

/// A CA and an EXPIRED `localhost` leaf it signed: (CA PEM, leaf PEM, leaf key PEM).
fn expired_ca() -> (String, String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = params.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf.not_before = date_time_ymd(2024, 1, 1);
    leaf.not_after = date_time_ymd(2024, 4, 1);
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    (ca_pem, leaf.pem(), leaf_key.serialize_pem())
}

#[test]
#[ignore = "fault suite: make e1-exit-faults"]
fn an_expired_certificate_is_reported_by_both_clients() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("ctl-f-expired-{}", std::process::id()));
    let (ca, leaf, key) = expired_ca();
    // ACME points at a closed local port: nothing leaves this machine, renewal fails.
    let listen = s(&[
        "--listen",
        &format!("public:{port}"),
        "--hostname",
        "localhost",
        "--acme-contact",
        "ops@example.com",
        "--acme-directory",
        "http://127.0.0.1:9/directory",
    ]);
    let core = Core::start_with(
        dir.join("x"),
        dir.join("x").join("admin.sock"),
        listen,
        Some(format!("localhost:{port}")),
        |home| {
            std::fs::create_dir_all(home.join("tls")).unwrap();
            std::fs::write(home.join("tls").join("cert.pem"), &leaf).unwrap();
            std::fs::write(home.join("tls").join("key.pem"), &key).unwrap();
        },
    );
    let ca_file = core.dir.join("ca.pem");
    std::fs::write(&ca_file, &ca).unwrap();
    let ca = ca_file.display().to_string();
    let url = format!("https://localhost:{port}");
    let ks = core.keystore("x").display().to_string();
    let o = ctl(&s(&[
        "--url",
        &url,
        "--ca",
        &ca,
        "--keystore",
        &ks,
        "pair",
        "ABCDE-FGHJK",
        "--no-stepup",
        "--wait",
        "1",
    ]));
    let ctl_err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert!(ctl_err.to_lowercase().contains("expired"), "{ctl_err}");
    let state = core.dir.join("runner").display().to_string();
    let o = Command::new(runner_bin())
        .args([
            "pair",
            &url,
            "--code",
            "ABCDE-FGHJK",
            "--ca",
            &ca,
            "--state",
            &state,
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let run_err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(!o.status.success(), "{o:?}");
    assert!(run_err.to_lowercase().contains("expired"), "{run_err}");
    assert!(!std::path::Path::new(&state).join("enrolment.json").exists());
    // The Core keeps serving and says loudly that its renewal failed.
    let start = Instant::now();
    while !core.log().contains("certificate order failed") {
        assert!(start.elapsed() < Duration::from_secs(20), "{}", core.log());
        std::thread::sleep(Duration::from_millis(200));
    }
    let core_line = core
        .log()
        .lines()
        .find(|l| l.contains("certificate order failed"))
        .unwrap()
        .to_owned();
    eprintln!(
        "FAULT cert-expired: ctl exit 1: {}; runner: {}; Core: {}",
        ctl_err.trim(),
        run_err.trim(),
        core_line.trim()
    );
    drop(core);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `GET /healthz` over a Unix socket: the status line, if any.
fn healthz(sock: &std::path::Path) -> Option<String> {
    let mut c = std::os::unix::net::UnixStream::connect(sock).ok()?;
    c.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    c.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut text = String::new();
    let _ = c.read_to_string(&mut text);
    text.lines().next().map(str::to_owned)
}

#[test]
#[ignore = "fault suite: make e1-exit-faults"]
fn a_read_only_database_fails_loudly() {
    let mut core = Core::start("f-readonly");
    core.kill9();
    let set = |mode: u32| {
        for p in [core.dir.join("core.db"), core.dir.clone()] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode | 0o400)).unwrap();
        }
    };
    let _ = std::fs::remove_file(core.dir.join("core.db-wal"));
    set(0o100);
    let mut child = Command::new(server_bin())
        .arg("serve")
        .arg(&core.db)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let outcome = loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
            break format!(
                "exited {status} in {:?}: {}",
                start.elapsed(),
                err.lines().last().unwrap_or("")
            );
        }
        if let Some(line) = healthz(&core.sock) {
            let _ = child.kill();
            let _ = child.wait();
            break format!("SERVED read-only ({line})");
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "neither failed nor served: a silent hang"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    set(0o300);
    assert!(
        outcome.starts_with("exited") && !outcome.contains("exit status: 0"),
        "{outcome}"
    );
    eprintln!("FAULT read-only-db: {outcome}");
}

#[test]
#[ignore = "fault suite: make e1-exit-faults"]
fn a_stalled_events_client_loses_nothing_and_slows_nobody() {
    let (core, url) = loopback_core("f-stall");
    let ks = core.keystore("mac");
    bootstrap(&core, &ks);
    let a = args(&[&s(&["--keystore", &ks.display().to_string()]), &core.at()]);
    let id = pair_runner(&core, &a, &url, "vm");
    let mark = head(&a);
    let mut tail = spawn_ctl(&args(&[
        &a,
        &s(&["events", "tail", "--after", &mark.to_string()]),
    ]));
    let mut lines = Lines::of(tail.stdout.take().unwrap());
    let pid = tail.id().to_string();
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        Command::new("kill")
            .args(["-STOP", &pid])
            .status()
            .unwrap()
            .success()
    );
    // While it is stopped (20 s past the renames): events keep coming and the Core answers others
    // at once. Ten renames, as each ctl run is several requests and the per-client burst is 120
    // (`api.request_burst`).
    let mut slowest = Duration::ZERO;
    for i in 0..10 {
        let o = ctl(&args(&[
            &a,
            &s(&["device", "rename", &id, &format!("vm-{i}")]),
        ]));
        assert!(o.status.success(), "{o:?}");
        let t = Instant::now();
        assert!(ctl(&args(&[&a, &s(&["health"])])).status.success());
        slowest = slowest.max(t.elapsed());
    }
    std::thread::sleep(Duration::from_secs(20));
    let end = head(&a);
    assert!(
        Command::new("kill")
            .args(["-CONT", &pid])
            .status()
            .unwrap()
            .success()
    );
    let mut seqs = Vec::new();
    while seqs.last() != Some(&end) {
        let line = lines
            .next(Duration::from_secs(30))
            .expect("the tail resumed");
        let e: serde_json::Value = serde_json::from_str(&line).unwrap();
        seqs.push(e["seq"].as_i64().unwrap());
    }
    let _ = tail.kill();
    let _ = tail.wait();
    let want: Vec<i64> = (mark + 1..=end).collect();
    assert_eq!(seqs, want, "the stalled client got every event once");
    assert!(slowest < Duration::from_secs(3), "{slowest:?}");
    eprintln!(
        "FAULT stalled-client: tail SIGSTOPped for ~{}s over {} events; resumed with {}..{} consecutive; \
         slowest health of another client meanwhile {slowest:?}",
        20 + 10 / 2,
        end - mark,
        mark + 1,
        end
    );
}
