//! Round-3 review fixes (PR #303), runner half: CPU below the wall clock, leftover job cgroups
//! swept, and Chromium bound only from a folder of its own.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{Command, DesignCheck, ErrorCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::oneshot;

use super::cgroup::sweep;
use super::sandbox::{LIMITS, cpu_secs};
use super::{DesignConfig, DesignDriver, chromium_ok};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "design-r3-{name}-{}-{:?}",
        std::process::id(),
        Instant::now()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn cpu_is_half_the_wall_clock() {
    assert_eq!(cpu_secs(Duration::from_secs(60)), 30);
    assert_eq!(cpu_secs(Duration::from_secs(1)), 1);
    assert!(LIMITS.contains("ulimit -S -t \"$1\""));
}

/// Spins the CPU: RLIMIT_CPU (3 s of a 6 s wall clock) ends it, a verdict on the file.
#[tokio::test]
async fn a_spinning_helper_is_a_failure_not_a_limit() {
    let dir = scratch("spin");
    let p = dir.join("ainkrad-design");
    std::fs::write(&p, "#!/bin/bash\nwhile :; do :; done\n").unwrap();
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let mut c = DesignConfig::new(p, None);
    c.timeout = Duration::from_secs(6);
    let cmd = Command::DesignCheck(DesignCheck {
        kind: "font".into(),
        data: STANDARD.encode(b"x"),
    });
    let (_keep, rx) = oneshot::channel();
    let e = DesignDriver::new(c).run(&cmd, rx).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignFailed, "{e:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn leftover_job_cgroups_are_swept_but_not_others() {
    let base = scratch("sweep");
    for d in ["design-aa", "design-bb", "runner"] {
        std::fs::create_dir(base.join(d)).unwrap();
    }
    // Stands in for a cgroup that still holds a process: a directory with content stays.
    std::fs::write(base.join("design-bb/cgroup.procs"), "1").unwrap();
    sweep(&base);
    assert!(!base.join("design-aa").exists());
    assert!(base.join("design-bb").exists(), "a busy cgroup was removed");
    assert!(base.join("runner").exists());
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn chromium_is_bound_only_from_a_folder_of_its_own() {
    let own = scratch("chromium");
    let shell = own.join("chrome-headless-shell");
    std::fs::write(&shell, "x").unwrap();
    std::fs::write(own.join("chrome.pak"), "x").unwrap();
    assert!(chromium_ok(&shell));
    // Beside the runner's or the helper's own files: never.
    std::fs::write(own.join("ainkrad-design"), "x").unwrap();
    assert!(!chromium_ok(&shell));
    // The runner's own folder (this test binary's).
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    assert!(!chromium_ok(&exe.with_file_name("chrome-headless-shell")));
    std::fs::remove_dir_all(own).unwrap();
}
