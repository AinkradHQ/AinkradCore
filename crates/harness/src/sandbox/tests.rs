use super::*;
use crate::proc::Proc;
use std::time::Duration;

fn fixture(name: &str) -> (PathBuf, Spec) {
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

fn mechanism_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    } // ignored owner test must fail, never skip
    let probe = std::process::Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .output();
    if !probe.is_ok_and(|o| o.status.success()) {
        assert!(
            std::env::var_os("AINKRAD_REQUIRE_SANDBOX").is_none(),
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

async fn run(spec: &Spec, program: &str, script: &str) -> (Option<i32>, String) {
    let args = vec!["-c".into(), script.into()];
    let mut cmd = crate::proc::command(OsStr::new(program), &args, spec, &[]);
    cmd.env("PATH", "/usr/bin:/bin");
    let mut child = Proc::spawn_with_pgid_file(cmd, None).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("sandbox probe timed out");
    (status, child.stderr_tail())
}

#[test]
fn profile_has_only_explicit_grants_and_no_keychain_service() {
    let (root, spec) = fixture("profile");
    let text = profile(&spec);
    assert!(text.starts_with("(version 1)\n(deny default)"));
    for dir in ["work", "config", "tmp"] {
        assert!(text.contains(root.join(dir).to_str().unwrap()));
    }
    for dir in ["home", "state", "other"] {
        assert!(!text.contains(root.join(dir).to_str().unwrap()));
    }
    assert!(!text.contains("keychain") && !text.contains("(allow network*)"));
    let mut allow = spec.clone();
    allow.env.retain(|(n, _)| n != "AINKRAD_SANDBOX_NETWORK");
    assert!(
        profile(&allow).contains("(allow network*)"),
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
        "/usr/bin/python3",
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
    let (code, err) = run(&spec, "/usr/bin/python3", &script).await;
    assert_eq!(code, Some(0), "deny network escaped: {err}");
    let mut allow = spec.clone();
    allow.env.retain(|(n, _)| n != "AINKRAD_SANDBOX_NETWORK");
    let (code, err) = run(&allow, "/usr/bin/python3", &script).await;
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
    let mut child = Proc::spawn_with_pgid_file(cmd, None).unwrap();
    let pgid = child.pgid;
    assert_eq!(child.line().await.as_deref(), Some("ready"));
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
        let (control, err) = run(&bounded, "/usr/bin/python3", "pass").await;
        assert_eq!(control, Some(0), "{name} control could not run: {err}");
        let (code, _) = run(&bounded, "/usr/bin/python3", script).await;
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
