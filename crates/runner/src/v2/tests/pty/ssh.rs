//! An interactive SSH terminal through `PtyOpen` (Leyline Y2-02), with the real `ainkrad-ptyhost`
//! and `ainkrad-runner ssh-pty`: it works like a local terminal (resume, resize), and the key,
//! which the Core's lease delivers as a `file` secret, is nowhere a process, a file or the terminal
//! could show it.

use ainkrad_proto::v2::{SshTerminal, TerminalInfo};
use russh::keys::ssh_key::LineEnding;

use super::*;
use crate::v2::ssh::fixture::{Leases, ssh};
use crate::v2::ssh::pty_tests::shell;

/// `ainkrad-runner`, built next to the tests (`cargo test -p ainkrad-runner`).
fn runner_bin() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap();
    [dir.to_path_buf(), dir.parent().unwrap().to_path_buf()]
        .into_iter()
        .map(|d| d.join("ainkrad-runner"))
        .find(|p| p.is_file())
        .expect("ainkrad-runner is built next to the tests (cargo test -p ainkrad-runner)")
}

fn open_ssh(target: ainkrad_proto::v2::SshHop) -> Body {
    Body::Command(Command::PtyOpen(PtyOpen {
        program: None,
        args: vec![],
        cwd: None,
        session: None,
        env: Default::default(),
        env_pass: vec![],
        size: Size { rows: 24, cols: 80 },
        watch: false,
        scrollback_bytes: None,
        scrollback_budget: None,
        ssh: Some(SshTerminal {
            target,
            hops: vec![],
        }),
    }))
}

/// Every file under `dir`, read.
fn files(dir: &std::path::Path, out: &mut Vec<Vec<u8>>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, out);
        } else if let Ok(b) = std::fs::read(&p) {
            out.push(b);
        }
    }
}

/// The command line and environment of every process that is `ssh-pty` or a terminal host.
#[cfg(target_os = "linux")]
fn process_text(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        let p = e.path();
        let Ok(cmd) = std::fs::read(p.join("cmdline")) else {
            continue;
        };
        let line = String::from_utf8_lossy(&cmd).replace('\0', " ");
        if line.contains("ssh-pty") || line.contains(&format!("serve --dir {}", dir.display())) {
            let mut all = cmd;
            all.extend(std::fs::read(p.join("environ")).unwrap_or_default());
            found.push((line, all));
        }
    }
    found
}

#[tokio::test]
async fn an_ssh_terminal_opens_through_pty_open_resumes_resizes_and_leaks_no_key() {
    let dir = tmp();
    let _reap = Reap(dir.clone());
    let s = shell(true, false, false).await;
    let leases = Leases::default();
    let key = leases.key("l_1");
    let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
    // A run of the key's own base64: what any copy of the key would contain.
    let seed = pem.lines().nth(1).unwrap().to_owned();
    let d = Arc::new(ssh(&leases).with_bin(runner_bin()));
    let (mut core, _) = Core::start_pty_ssh(driver(&dir, true), d).await;

    core.send(1, open_ssh(s.hop("me", "l_1"))).await;
    let mut out = String::new();
    let Body::Control(Control::Opened(TerminalInfo { terminal: id, .. })) =
        until(&mut core, 1, &mut out, |_, _| true).await
    else {
        panic!("opened first")
    };
    until(&mut core, 1, &mut out, |o, _| o.contains("ready")).await;
    core.send(1, input("hello\r")).await;
    until(&mut core, 1, &mut out, |o, _| o.contains("got:hello")).await;

    // The key is in no argv or environment of the terminal's processes.
    #[cfg(target_os = "linux")]
    {
        let procs = process_text(&dir);
        assert!(
            procs.iter().any(|(l, _)| l.contains("ssh-pty")),
            "ssh-pty runs: {procs:?}"
        );
        for (line, all) in &procs {
            let all = String::from_utf8_lossy(all);
            assert!(!all.contains(&seed), "the key is in {line}");
        }
    }

    // Resize reaches the remote pty.
    core.send(
        1,
        Body::Control(Control::Resize(Size {
            rows: 30,
            cols: 100,
        })),
    )
    .await;
    for _ in 0..200 {
        if !s.log.windows.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(*s.log.windows.lock().unwrap(), [(100, 30)], "cols, rows");

    // Detach: the terminal (and its ssh connection) keeps running; attach resumes from byte 0.
    core.send(1, Body::Close(Close::default())).await;
    until(&mut core, 1, &mut out, |_, b| matches!(b, Body::Error(_))).await;
    core.send(
        3,
        Body::Command(Command::PtyAttach(PtyAttach {
            terminal: id.clone(),
            seq: 0,
            watch: false,
        })),
    )
    .await;
    let mut again = String::new();
    until(&mut core, 3, &mut again, |o, _| o.contains("got:hello")).await;
    assert!(again.contains("ready"), "scrollback replays: {again:?}");
    core.send(3, input("more\r")).await;
    until(&mut core, 3, &mut again, |o, _| o.contains("got:more")).await;

    // The remote shell's end is the terminal's exit.
    core.send(3, input("exit\r")).await;
    let end = until(&mut core, 3, &mut again, |_, b| {
        matches!(b, Body::Result(_) | Body::Error(_))
    })
    .await;
    let Body::Result(Reply::PtyAttach(exit)) = end else {
        panic!("{end:?}")
    };
    assert_eq!(exit.exit_code, Some(5));

    // The key is not in anything the terminal showed, nor in a file the host wrote.
    assert!(!out.contains(&seed) && !again.contains(&seed));
    let mut all = Vec::new();
    files(&dir, &mut all);
    assert!(!all.is_empty(), "the terminal host wrote its record");
    for f in all {
        assert!(
            !String::from_utf8_lossy(&f).contains(&seed),
            "the key is on disk"
        );
    }
}

#[tokio::test]
async fn an_ssh_terminal_with_a_wrong_host_key_shows_the_fingerprint_and_authenticates_nothing() {
    let dir = tmp();
    let _reap = Reap(dir.clone());
    let s = shell(true, true, true).await;
    let leases = Leases::default();
    leases.key("l_1");
    let d = Arc::new(ssh(&leases).with_bin(runner_bin()));
    let (mut core, _) = Core::start_pty_ssh(driver(&dir, true), d).await;
    let mut hop = s.hop("me", "l_1");
    hop.pinned_keys = vec![crate::v2::ssh::fixture::fp(
        &crate::v2::ssh::fixture::new_key(),
    )];
    core.send(1, open_ssh(hop)).await;
    let mut out = String::new();
    let end = until(&mut core, 1, &mut out, |_, b| {
        matches!(b, Body::Result(_) | Body::Error(_))
    })
    .await;
    let Body::Result(Reply::PtyOpen(exit)) = end else {
        panic!("{end:?}")
    };
    assert_eq!(exit.exit_code, Some(71), "host key changed: {out:?}");
    assert!(
        out.contains(&crate::v2::ssh::fixture::fp(&s.host_key)),
        "{out:?}"
    );
    assert_eq!(
        s.log.auths.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing was authenticated"
    );
}

#[tokio::test]
async fn an_ssh_terminal_is_refused_without_the_ssh_driver_or_with_a_program() {
    let dir = tmp();
    let _reap = Reap(dir.clone());
    let s = shell(true, false, false).await;
    // No ssh driver on this runner.
    let (mut core, _) = Core::start_pty(driver(&dir, true)).await;
    core.send(1, open_ssh(s.hop("me", "l_1"))).await;
    assert_eq!(error(core.answer(1).await), ErrorCode::UnsupportedCommand);
    // An ssh terminal names no program of its own.
    let leases = Leases::default();
    leases.key("l_1");
    let d = Arc::new(ssh(&leases).with_bin(runner_bin()));
    let (mut core, _) = Core::start_pty_ssh(driver(&dir, true), d).await;
    let Body::Command(Command::PtyOpen(mut o)) = open_ssh(s.hop("me", "l_1")) else {
        unreachable!()
    };
    o.program = Some("/bin/sh".to_owned());
    core.send(1, Body::Command(Command::PtyOpen(o))).await;
    assert_eq!(error(core.answer(1).await), ErrorCode::InvalidArgs);
}

/// The production default: the terminal sandbox is on, and the key handoff (an inherited descriptor)
/// still reaches `ssh-pty` through bubblewrap or Seatbelt.
#[tokio::test]
async fn an_ssh_terminal_works_under_the_terminal_sandbox() {
    let dir = tmp();
    let _reap = Reap(dir.clone());
    let s = shell(true, false, false).await;
    let leases = Leases::default();
    leases.key("l_1");
    let d = Arc::new(ssh(&leases).with_bin(runner_bin()));
    let pty = sandboxed_driver(&dir, Some(Vec::new()), vec![]);
    let (mut core, _) = Core::start_pty_ssh(pty, d).await;
    core.send(1, open_ssh(s.hop("me", "l_1"))).await;
    let mut out = String::new();
    until(&mut core, 1, &mut out, |o, b| {
        o.contains("ready") || matches!(b, Body::Error(_) | Body::Result(_))
    })
    .await;
    assert!(out.contains("ready"), "{out:?}");
    core.send(1, input("hello\r")).await;
    until(&mut core, 1, &mut out, |o, _| o.contains("got:hello")).await;
}
