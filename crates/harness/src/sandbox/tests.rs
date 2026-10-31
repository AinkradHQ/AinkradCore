use super::*;
use crate::proc::Proc;
use std::time::Duration;

pub(super) fn fixture(name: &str) -> (PathBuf, Spec) {
    let root = std::env::temp_dir().join(format!("sandbox-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for dir in ["home/.ssh", "work", "tmp", "state/other", "config"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    for file in [
        "home/.ssh/canary",
        "state/key",
        "state/other/secret",
        "outside",
    ] {
        std::fs::write(root.join(file), "canary").unwrap();
    }
    let root = root.canonicalize().unwrap();
    let spec = Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env: vec![
            ("AINKRAD_SANDBOX".into(), "1".into()),
            ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
            ("AINKRAD_SANDBOX_STATE".into(), root.join("state").into()),
            ("AINKRAD_SANDBOX_NETWORK".into(), "deny".into()),
            ("AINKRAD_SANDBOX_PROCESSES".into(), "16".into()),
            ("HOME".into(), root.join("home").into()),
            ("CANARY_ROOT".into(), root.clone().into()),
        ],
        ..Spec::default()
    };
    (root, spec)
}

pub(super) fn mechanism_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    } // ignored owner test must fail, never skip
    let probe = std::process::Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .output();
    if !probe.is_ok_and(|o| o.status.success()) {
        assert!(
            std::env::var_os("AINKRAD_REQUIRE_SANDBOX").is_none_or(|v| v.is_empty()),
            "required bubblewrap/user namespaces cannot run"
        );
        // Bypass libtest's success-output capture: a skipped enforcement probe must
        // be visible even in an ordinary `make test` log without --nocapture.
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "SKIP SANDBOX ENFORCEMENT: bubblewrap/user namespaces cannot run on this host"
        );
        return false;
    }
    true
}

/// A real interpreter, never the /usr/bin shim: on macOS that shim runs xcode-select, so a
/// failure through it would say nothing about enforcement. Resolved outside the sandbox.
pub(super) fn python() -> String {
    if cfg!(target_os = "macos") {
        let clt = "/Library/Developer/CommandLineTools/usr/bin/python3";
        if Path::new(clt).exists() {
            return clt.into();
        }
        if let Ok(o) = std::process::Command::new("/usr/bin/xcrun")
            .args(["--find", "python3"])
            .output()
        {
            let p = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            if o.status.success() && Path::new(&p).is_absolute() {
                return p;
            }
        }
    }
    "/usr/bin/python3".into()
}

pub(super) async fn run(spec: &Spec, program: &str, script: &str) -> (Option<i32>, String) {
    let args = vec!["-c".into(), script.into()];
    let mut cmd = crate::proc::command(OsStr::new(program), &args, spec, &[]);
    cmd.env("PATH", "/usr/bin:/bin");
    diag_profile(spec, program);
    let mut child = Proc::spawn_with_pgid_file(cmd, None).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("sandbox probe timed out");
    (status, outcome(&child, status))
}

/// "exit=Some(0) signal=None stderr=..": a sandbox kill shows as a signal, not an exit code.
pub(super) fn outcome(child: &Proc, status: Option<i32>) -> String {
    let out = format!(
        "exit={status:?} signal={:?} stderr={}",
        child.signal,
        child.stderr_tail()
    );
    if std::env::var_os("AINKRAD_SANDBOX_DIAG").is_some() {
        eprintln!("DIAG {out}");
    }
    out
}

/// With `AINKRAD_SANDBOX_DIAG=1` (scripts/sandbox-macos-test.sh) print the generated profile.
pub(super) fn diag_profile(spec: &Spec, program: &str) {
    if std::env::var_os("AINKRAD_SANDBOX_DIAG").is_some() {
        eprintln!(
            "DIAG program={program}\nDIAG profile:\n{}",
            profile(spec, OsStr::new(program))
        );
    }
}

#[test]
fn macos_profile_has_no_blanket_network_and_no_unix_sockets() {
    let (root, spec) = fixture("netprofile");
    let mut allow = spec.clone();
    allow.env.retain(|(n, _)| n != "AINKRAD_SANDBOX_NETWORK");
    let text = profile(&allow, OsStr::new("/bin/true"));
    assert!(
        !text.contains("network*"),
        "a blanket grant covers AF_UNIX sockets"
    );
    assert!(text.contains("(remote tcp \"*:443\")"));
    assert!(!text.contains("remote tcp \"*:80\"") && !text.contains("169.254"));
    // The only unix socket granted is the DNS resolver's.
    assert_eq!(text.matches("(allow network-outbound (literal").count(), 1);
    assert!(!text.contains("docker") && !text.contains("ssh-agent"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn macos_profile_boots_from_system_sb_and_keeps_explicit_denies() {
    let (root, spec) = fixture("golden");
    let text = profile(&spec, OsStr::new("/bin/true"));
    let at = |needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };
    // The base profile every process needs to start, right after the default deny.
    assert!(at("(deny default)") < at("(import \"system.sb\")"));
    assert!(text.contains("(allow file-read* file-map-executable (subpath \"/usr\"))"));
    assert!(text.contains("(subpath \"/System/Library\")"));
    // The Xcode shims' developer-dir lookup: that one symlink, read-only, nothing wider.
    assert!(text.contains("(allow file-read* (literal \"/private/var/db/xcode_select_link\"))"));
    assert!(text.contains("(allow file-read* (literal \"/var/db/xcode_select_link\"))"));
    assert!(
        !text.contains("(subpath \"/private/var/db\")") && !text.contains("(subpath \"/var\")")
    );
    // Explicit denies for the state dir, the fake home's ssh keys and every unix socket,
    // emitted before the session grants.
    let state = root.join("state");
    let deny_state = format!(
        "(deny file-read* file-write* (subpath \"{}\"))",
        state.display()
    );
    let ssh = format!(
        "(deny file-read* file-write* (subpath \"{}\"))",
        root.join("home/.ssh").display()
    );
    assert!(text.contains(&deny_state) && text.contains(&ssh));
    assert!(text.contains("(deny network-outbound (remote unix-socket))"));
    let work = format!(
        "(allow file-read* file-write* (subpath \"{}\"))",
        root.join("work").display()
    );
    assert!(at(&deny_state) < at(&work) && at(&ssh) < at(&work));
    // Ancestors are stat-able by name only; the worktree itself is the only write grant.
    assert!(text.contains(&format!(
        "(allow file-read-metadata (literal \"{}\"))",
        root.display()
    )));
    for line in text
        .lines()
        .filter(|l| l.contains("file-write*") && l.starts_with("(allow"))
    {
        let p = ["work", "config", "tmp"].map(|d| root.join(d));
        assert!(
            p.iter().any(|p| line.contains(p.to_str().unwrap())) || line.contains("/dev/null"),
            "{line}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_harness_install_dir_is_granted_read_only_but_never_a_home_or_root() {
    let (root, spec) = fixture("progdir");
    std::fs::create_dir_all(root.join("tools")).unwrap();
    std::fs::write(root.join("tools/stub"), "#!/bin/bash\n").unwrap();
    let dirs = program_dirs(root.join("tools/stub").as_os_str(), &spec);
    assert_eq!(dirs, [root.join("tools")]);
    assert!(
        program_dirs(OsStr::new("/bin/bash"), &spec).is_empty(),
        "toolchain path"
    );
    assert!(
        program_dirs(OsStr::new("/stub"), &spec).is_empty(),
        "root dir"
    );
    assert!(
        program_dirs(spec.cwd.join("x").as_os_str(), &spec).is_empty(),
        "own worktree"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn profile_has_only_explicit_grants_and_no_keychain_service() {
    let (root, spec) = fixture("profile");
    let text = profile(&spec, OsStr::new("/bin/true"));
    assert!(text.starts_with("(version 1)\n(deny default)"));
    for dir in ["work", "config", "tmp"] {
        assert!(text.contains(root.join(dir).to_str().unwrap()));
    }
    for dir in ["home", "state", "other"] {
        let path = root.join(dir);
        assert!(
            !text
                .lines()
                .filter(|l| l.starts_with("(allow"))
                .any(|l| l.contains(path.to_str().unwrap())),
            "{dir} granted"
        );
    }
    assert!(!text.contains("keychain") && !text.contains("(allow network*)"));
    let mut allow = spec.clone();
    allow.env.retain(|(n, _)| n != "AINKRAD_SANDBOX_NETWORK");
    assert!(
        profile(&allow, OsStr::new("/bin/true")).contains("(allow network-outbound (remote tcp"),
        "network defaults to allow"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: run scripts/sandbox-macos-test.sh in a normal Terminal; Seatbelt cannot nest"
)]
async fn process_sandbox_denies_a_fake_home_canary() {
    if !mechanism_available() {
        return;
    }
    let (root, spec) = fixture("enforcement");
    // These controls prove the planted files are readable and the outside directory writable.
    assert_eq!(
        std::fs::read_to_string(root.join("home/.ssh/canary")).unwrap(),
        "canary"
    );
    assert!(std::fs::read(root.join("state/key")).is_ok());
    assert!(std::fs::read(root.join("state/other/secret")).is_ok());
    std::fs::write(root.join("outside"), "writable").unwrap();
    let (code, err) = run(
        &spec,
        "/bin/bash",
        r#"
        test ! -r "$HOME/.ssh/canary" &&
        test ! -r "$CANARY_ROOT/state/key" &&
        test ! -r "$CANARY_ROOT/state/other/secret" &&
        ! cat "$CANARY_ROOT/outside" &&
        ! echo escape > "$CANARY_ROOT/outside" &&
        echo ok > allowed
    "#,
    )
    .await;
    assert_eq!(code, Some(0), "filesystem denial failed: {err}");
    assert_eq!(
        std::fs::read_to_string(root.join("work/allowed")).unwrap(),
        "ok\n"
    );
    let (code, err) = run(
        &spec,
        &python(),
        r#"
import os, time, sys
for i in range(128):
    try: pid = os.fork()
    except BlockingIOError: sys.exit(0)
    if pid == 0:
        time.sleep(60)
        os._exit(0)
sys.exit(99)
"#,
    )
    .await;
    assert_eq!(code, Some(0), "fork limit did not deny spawning: {err}");
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let script = format!(
        "import socket, sys\ns=socket.socket()\ns.settimeout(1)\ntry: s.connect(('127.0.0.1', {}))\nexcept OSError: sys.exit(0)\nsys.exit(99)",
        listener.local_addr().unwrap().port()
    );
    let (code, err) = run(&spec, &python(), &script).await;
    assert_eq!(code, Some(0), "deny network escaped: {err}");
    let mut allow = spec.clone();
    allow.env.retain(|(n, _)| n != "AINKRAD_SANDBOX_NETWORK");
    let (code, err) = run(&allow, &python(), &script).await;
    assert_eq!(
        code,
        Some(99),
        "network allow control could not connect: {err}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: run scripts/sandbox-macos-test.sh"
)]
async fn sandbox_timeout_kills_whole_group() {
    if !mechanism_available() {
        return;
    }
    let (root, spec) = fixture("timeout");
    let mut cmd = crate::proc::command(
        OsStr::new("/bin/bash"),
        &["-c".into(), "sleep 600 & echo ready; wait".into()],
        &spec,
        &[],
    );
    cmd.env("PATH", "/usr/bin:/bin");
    diag_profile(&spec, "/bin/bash");
    let mut child = Proc::spawn_with_pgid_file(cmd, None).unwrap();
    let pgid = child.pgid;
    let first = child.line().await;
    assert_eq!(
        first.as_deref(),
        Some("ready"),
        "signal={:?} stderr={}",
        child.signal,
        child.stderr_tail()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), child.wait())
            .await
            .is_err()
    );
    drop(child);
    for _ in 0..100 {
        let out = std::process::Command::new("ps")
            .args(["-A", "-o", "pgid=,stat="])
            .output()
            .unwrap();
        let live = String::from_utf8_lossy(&out.stdout).lines().any(|line| {
            let mut cols = line.split_whitespace();
            cols.next().and_then(|s| s.parse::<u32>().ok()) == Some(pgid)
                && !cols.next().unwrap_or("").starts_with('Z')
        });
        if !live {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("a sandbox process survived its timeout");
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: run scripts/sandbox-macos-test.sh"
)]
async fn sandbox_resource_overruns_are_terminated() {
    if !mechanism_available() {
        return;
    }
    let (root, spec) = fixture("budgets");
    for (name, value, script) in [
        ("AINKRAD_SANDBOX_CPU", "1", "while True: pass"),
        (
            "AINKRAD_SANDBOX_CPU",
            "2",
            "import os,time\nfor _ in range(2):\n p=os.fork()\n if p==0:\n  start=time.process_time()\n  while time.process_time()-start<1.6: pass\n  os._exit(0)\nfor _ in range(2): os.wait()",
        ),
        (
            "AINKRAD_SANDBOX_MEMORY",
            "65536",
            "x=bytearray(128*1024*1024); import time; time.sleep(60)",
        ),
        (
            "AINKRAD_SANDBOX_FILE",
            "64",
            "open('large','wb').write(bytes(1024*1024))",
        ),
        (
            "AINKRAD_SANDBOX_DISK",
            "64",
            "open('a','wb').write(bytes(512*1024)); import time; time.sleep(60)",
        ),
    ] {
        let mut bounded = spec.clone();
        bounded.env.push((name.into(), value.into()));
        let (control, err) = run(&bounded, &python(), "pass").await;
        assert_eq!(control, Some(0), "{name} control could not run: {err}");
        let (code, _) = run(&bounded, &python(), script).await;
        assert_ne!(code, Some(0), "{name} allowed the overrun");
    }
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn an_invalid_manifest_cannot_spawn_an_agent() {
    let (root, mut spec) = fixture("invalid");
    spec.env
        .push(("AINKRAD_SANDBOX_CPU".into(), "invalid".into()));
    let cmd = crate::proc::command(
        OsStr::new("/bin/bash"),
        &["-c".into(), "touch escaped".into()],
        &spec,
        &[],
    );
    assert!(Proc::spawn_with_pgid_file(cmd, None).is_err());
    assert!(!root.join("work/escaped").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: run scripts/sandbox-macos-test.sh"
)]
async fn sockets_nested_userns_shm_and_the_harness_binary() {
    if !mechanism_available() {
        return;
    }
    let (root, spec) = fixture("sockets");
    // A same-uid unix socket on the host (ptyhost, docker, ssh-agent in real life).
    let sock = root.join("state/host.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let connect = format!(
        "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect({:?})\nexcept OSError: sys.exit(0)\nsys.exit(99)",
        sock
    );
    let (code, err) = run(&spec, &python(), &connect).await;
    assert_eq!(code, Some(0), "a host unix socket was reachable: {err}");
    // The control proves the socket accepts a plain connection.
    assert!(std::os::unix::net::UnixStream::connect(&sock).is_ok());
    // The harness binary, outside the toolchain paths, runs and is read-only.
    std::fs::create_dir_all(root.join("tools")).unwrap();
    let stub = root.join("tools/stub");
    std::fs::write(
        &stub,
        "#!/bin/bash\necho ok > ran\n! echo x > \"$(dirname \"$0\")/w\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    diag_profile(&spec, stub.to_str().unwrap());
    let cmd = crate::proc::command(stub.as_os_str(), &[], &spec, &[]);
    let mut child = Proc::spawn_with_pgid_file(cmd, None).unwrap();
    let code = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .unwrap();
    assert_eq!(code, Some(0), "stub: {}", outcome(&child, code));
    assert!(root.join("work/ran").exists() && !root.join("tools/w").exists());
    #[cfg(target_os = "linux")]
    {
        // Abstract sockets live in the network namespace: hidden by `deny`, and the
        // documented residual of `allow` (the host network).
        let name = format!("ainkrad-test-{}", std::process::id());
        let l = {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(&name).unwrap();
            std::os::unix::net::UnixListener::bind_addr(&addr).unwrap()
        };
        let abstract_connect = format!(
            "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect('\\0{name}')\nexcept OSError: sys.exit(0)\nsys.exit(99)"
        );
        let (code, err) = run(&spec, &python(), &abstract_connect).await;
        assert_eq!(code, Some(0), "deny reached an abstract socket: {err}");
        let mut allow = spec.clone();
        allow.env.retain(|(n, _)| n != "AINKRAD_SANDBOX_NETWORK");
        let (code, _) = run(&allow, &python(), &abstract_connect).await;
        assert_eq!(
            code,
            Some(99),
            "residual changed: update the documented policy"
        );
        drop(l);
        // No nested user namespace (it would reset the process cap), and a sized /dev/shm.
        let (code, err) = run(&spec, "/bin/bash", "! /usr/bin/unshare -U /bin/true").await;
        assert_eq!(code, Some(0), "nested userns allowed: {err}");
        let (code, err) = run(
            &spec,
            "/bin/bash",
            "! head -c 67108864 /dev/zero > /dev/shm/big",
        )
        .await;
        assert_eq!(code, Some(0), "/dev/shm unbounded: {err}");
    }
    let _ = std::fs::remove_dir_all(root);
}

/// B-H2: a session on the `deny` policy (the default for one that holds secrets) reaches
/// neither a TCP canary on the host's loopback nor the cloud metadata address.
#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: run scripts/sandbox-macos-test.sh"
)]
async fn a_denied_network_reaches_no_loopback_canary_and_no_metadata_address() {
    if !mechanism_available() {
        return;
    }
    let (root, spec) = fixture("netdeny");
    let canary = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = canary.local_addr().unwrap().port();
    // bash's /dev/tcp: no interpreter outside the toolchain paths is needed.
    let probe = |host: &str, port: u16| {
        format!("(exec 3<>/dev/tcp/{host}/{port}) 2>/dev/null && exit 99; exit 0")
    };
    for (host, port) in [("127.0.0.1", port), ("169.254.169.254", 80)] {
        let (code, err) = run(&spec, "/bin/bash", &probe(host, port)).await;
        assert_eq!(code, Some(0), "{host}:{port} was reachable: {err}");
    }
    // The control: the same probe, unsandboxed, reaches the canary.
    let open = std::process::Command::new("/bin/bash")
        .args(["-c", &probe("127.0.0.1", port)])
        .status()
        .unwrap();
    assert_eq!(open.code(), Some(99));
    let _ = std::fs::remove_dir_all(root);
}
