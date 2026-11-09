use std::sync::Arc;
use std::time::Duration;

use super::fake::{FakeVm, Script};
use super::*;
use crate::proc::Proc;

fn spec(dir: &std::path::Path, backend: Option<Arc<dyn ExecBackend>>) -> Spec {
    Spec {
        cwd: dir.to_path_buf(),
        env_allow: vec!["PATH".to_owned()],
        backend,
        ..Spec::default()
    }
}

fn sh(script: &str) -> Launch {
    Launch::new("sh", vec!["-c".to_owned(), script.to_owned()])
}

/// A scratch directory removed when it goes out of scope.
struct Dir(std::path::PathBuf);

impl Dir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir() -> Dir {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!("ainkrad-exec-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&path).expect("scratch dir");
    Dir(path)
}

#[tokio::test]
async fn the_default_backend_runs_the_launch_locally() {
    let d = dir();
    let mut p = Proc::start(&spec(d.path(), None), sh("echo hi; echo oops >&2; exit 3"))
        .await
        .unwrap();
    assert_eq!(p.line().await.as_deref(), Some("hi"));
    assert_eq!(p.wait().await, Some(3));
    assert_eq!(p.stderr_tail(), "oops");
    assert_eq!(p.exit.map(|e| (e.code, e.deadline)), Some((Some(3), false)));
}

#[tokio::test]
async fn the_local_launch_is_the_command_the_adapters_always_built() {
    let d = dir();
    let s = spec(d.path(), None);
    let launch = sh("true").set("HOME", s.cwd.as_os_str());
    let built = launch.command(&s);
    let direct = crate::proc::command(
        std::ffi::OsStr::new("sh"),
        &["-c".to_owned(), "true".to_owned()],
        &s,
        &[("HOME", s.cwd.as_os_str())],
    );
    assert_eq!(
        format!("{:?}", built.as_std()),
        format!("{:?}", direct.as_std())
    );
}

#[tokio::test]
async fn the_local_backend_refuses_a_pty_instead_of_pretending() {
    let d = dir();
    let s = spec(d.path(), None);
    let launch = sh("true");
    let err = LocalBackend
        .spawn(SpawnRequest {
            spec: &s,
            launch: &launch,
            stdio: Stdio::Pty { rows: 24, cols: 80 },
            deadline: None,
        })
        .await
        .err()
        .expect("a pty must be refused");
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
}

#[tokio::test]
async fn a_refusing_backend_starts_nothing_and_never_falls_back_to_local() {
    let d = dir();
    let marker = d.path().join("ran");
    let script = format!("touch {}", marker.display());
    let vm = FakeVm::new(Script::Refuse("no kvm".into()));
    let err = Proc::start(&spec(d.path(), Some(vm.clone())), sh(&script))
        .await
        .err()
        .expect("refused");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("no kvm"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!marker.exists(), "a refused start ran locally");
    assert_eq!(vm.started.load(std::sync::atomic::Ordering::SeqCst), 0);
    // Control: the same launch does run on the local backend, so the check can fail.
    let mut p = Proc::start(&spec(d.path(), None), sh(&script))
        .await
        .unwrap();
    p.wait().await;
    assert!(marker.exists());
}

#[tokio::test]
async fn a_pty_request_to_the_fake_is_refused_too() {
    let d = dir();
    let s = spec(d.path(), None);
    let vm = FakeVm::new(Script::Exit {
        stdout: vec![],
        stderr: String::new(),
        exit: Exit::default(),
    });
    let launch = sh("true");
    let req = SpawnRequest {
        spec: &s,
        launch: &launch,
        stdio: Stdio::Pty { rows: 1, cols: 1 },
        deadline: None,
    };
    assert!(vm.spawn(req).await.is_err());
    assert_eq!(vm.started.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_backend_that_dies_mid_run_reports_the_kill_and_its_output_so_far() {
    let d = dir();
    let vm = FakeVm::new(Script::Exit {
        stdout: vec!["one".into(), "two".into()],
        stderr: "vm lost".into(),
        exit: Exit {
            code: None,
            signal: Some(9),
            deadline: false,
            oom: true,
        },
    });
    let mut p = Proc::start(&spec(d.path(), Some(vm.clone())), sh("ignored"))
        .await
        .unwrap();
    assert_eq!(p.line().await.as_deref(), Some("one"));
    assert_eq!(p.line().await.as_deref(), Some("two"));
    assert_eq!(p.line().await, None);
    assert_eq!(p.wait().await, None);
    assert_eq!(p.signal, Some(9));
    assert!(p.exit.is_some_and(|e| e.oom && !e.deadline));
    assert_eq!(p.stderr_tail(), "vm lost");
}

#[tokio::test]
async fn the_wall_clock_cap_reaches_the_backend_and_ends_a_hung_guest() {
    let d = dir();
    let vm = FakeVm::new(Script::Hang { stdout: vec![] });
    let mut s = spec(d.path(), Some(vm.clone()));
    s.env.push((WALL_VAR.to_owned(), "1".into()));
    let mut p = Proc::start(&s, sh("ignored")).await.unwrap();
    assert_eq!(vm.seen()[0].deadline, Some(Duration::from_secs(1)));
    assert_eq!(p.line().await, None);
    p.wait().await;
    assert!(p.exit.is_some_and(|e| e.deadline && e.signal == Some(9)));
}

#[tokio::test]
async fn no_cap_means_no_timer_and_a_bad_cap_refuses_the_start() {
    let d = dir();
    let vm = FakeVm::new(Script::Hang { stdout: vec![] });
    let p = Proc::start(&spec(d.path(), Some(vm.clone())), sh("x"))
        .await
        .unwrap();
    assert_eq!(vm.seen()[0].deadline, None);
    drop(p);
    for bad in ["0", "abc", "-1", "86401", ""] {
        let mut s = spec(d.path(), Some(vm.clone()));
        s.env.push((WALL_VAR.to_owned(), bad.into()));
        let err = Proc::start(&s, sh("x")).await.err().expect(bad);
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad}");
    }
    assert_eq!(vm.started.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_local_wall_clock_cap_kills_the_whole_group() {
    let d = dir();
    let mut s = spec(d.path(), None);
    s.env.push((WALL_VAR.to_owned(), "1".into()));
    let mut p = Proc::start(&s, sh("sleep 600 & sleep 600")).await.unwrap();
    let started = std::time::Instant::now();
    assert_eq!(p.line().await, None);
    p.wait().await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(p.exit.is_some_and(|e| e.deadline && e.signal == Some(9)));
}

#[tokio::test]
async fn dropping_the_handle_destroys_the_guest() {
    let d = dir();
    let vm = FakeVm::new(Script::Hang { stdout: vec![] });
    let p = Proc::start(&spec(d.path(), Some(vm.clone())), sh("x"))
        .await
        .unwrap();
    assert_eq!(vm.torn_down.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(p);
    assert_eq!(vm.torn_down.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn kill_and_stop_end_a_hung_guest() {
    let d = dir();
    let vm = FakeVm::new(Script::Hang { stdout: vec![] });
    let p = Proc::start(&spec(d.path(), Some(vm.clone())), sh("x"))
        .await
        .unwrap();
    assert_eq!(p.kill().await, None);
    let p = Proc::start(&spec(d.path(), Some(vm.clone())), sh("x"))
        .await
        .unwrap();
    // EOF on stdin does not end a hung guest; stop kills it after its grace.
    let stopped = tokio::time::timeout(Duration::from_secs(8), p.stop()).await;
    assert_eq!(stopped.expect("stop returned"), None);
}
