//! Orphans: whatever the agent starts, `setsid` escapes included, dies with its session or
//! with the runner. Every test kills what it started through a Drop guard.
use super::tests::{fixture, mechanism_available};
use super::*;
use crate::proc::Proc;
use std::time::Duration;

/// Kills the groups, pids and `sleep <marker>` processes it holds, whatever happens to the
/// test (a failed assertion must not leak a `setsid` sleeper).
struct Guard(Vec<u32>, Vec<&'static str>);
impl Drop for Guard {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = ainkrad_sys::killpg(*p, 9);
            let _ = ainkrad_sys::kill_pid(*p, 9);
        }
        for m in &self.1 {
            for pid in pids(m) {
                let _ = ainkrad_sys::kill_pid(pid, 9);
            }
        }
    }
}

/// Live (non-zombie) `sleep <marker>` processes.
fn pids(marker: &str) -> Vec<u32> {
    let out = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,stat=,args="])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut c = l.split_whitespace();
            let pid = c.next()?.parse().ok()?;
            let stat = c.next()?;
            let prog = c.next()?;
            let arg = c.next()?;
            (!stat.starts_with('Z') && prog.ends_with("sleep") && arg == marker).then_some(pid)
        })
        .collect()
}
fn alive(marker: &str) -> usize {
    pids(marker).len()
}
/// The escapee takes a moment to exec after the shell reports it started.
async fn running(marker: &str) -> bool {
    for _ in 0..100 {
        if alive(marker) == 1 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}
async fn gone(marker: &str) -> bool {
    for _ in 0..100 {
        if alive(marker) == 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[test]
fn the_tracker_follows_a_setsid_child_after_the_leader_is_gone() {
    let mut leader = {
        use std::os::unix::process::CommandExt;
        std::process::Command::new("/bin/bash")
            .args([
                "-c",
                "perl -MPOSIX -e \'POSIX::setsid(); exec q(sleep), q(8801)\' & wait",
            ])
            .process_group(0)
            .spawn()
            .unwrap()
    };
    let tracker = tree::Tracker::new(leader.id());
    let _guard = Guard(vec![leader.id()], vec!["8801"]);
    let mut seen = false;
    for _ in 0..100 {
        let snap = tree::snapshot().unwrap();
        seen = tracker.members(&snap).len() >= 2;
        if seen {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(seen, "the setsid child was not tracked");
    tracker.kill();
    let _ = leader.wait();
    for _ in 0..100 {
        if alive("8801") == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("a setsid escapee survived the tree kill");
}

#[test]
#[allow(clippy::zombie_processes)] // the guard kills them; a failed assertion must not hang on wait
fn the_supervisor_kills_the_tree_when_the_runner_dies() {
    use std::os::unix::process::CommandExt;
    let mut runner = std::process::Command::new("/bin/sleep")
        .arg("8802")
        .spawn()
        .unwrap();
    let mut leader = std::process::Command::new("/bin/bash")
        .args([
            "-c",
            "perl -MPOSIX -e \'POSIX::setsid(); exec q(sleep), q(8803)\' & wait",
        ])
        .process_group(0)
        .spawn()
        .unwrap();
    let mut sup = tree::supervise(leader.id(), runner.id()).unwrap();
    let _guard = Guard(vec![leader.id(), sup.id(), runner.id()], vec!["8803"]);
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(
        alive("8803"),
        1,
        "control: the escapee runs while the runner lives"
    );
    runner.kill().unwrap(); // the runner dies (kill -9)
    let _ = runner.wait();
    for _ in 0..100 {
        if alive("8803") == 0 {
            let _ = leader.wait();
            let _ = sup.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the supervisor left the tree running after the runner died");
}

#[tokio::test]
async fn a_leader_that_exits_leaving_a_member_is_still_reaped_from_its_record() {
    let (root, spec) = fixture("reapgroup");
    let record = root.join("pgid");
    let mut cmd = crate::proc::command(
        OsStr::new("/bin/bash"),
        &["-c".into(), "sleep 8804 & echo ready".into()],
        &Spec {
            env: vec![],
            ..spec
        },
        &[],
    );
    cmd.env("PATH", "/usr/bin:/bin");
    let mut child = Proc::spawn_with_pgid_file(cmd, Some(record.clone())).unwrap();
    let _guard = Guard(vec![child.pgid], vec!["8804"]);
    assert_eq!(child.line().await.as_deref(), Some("ready"));
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .is_ok()
    );
    let text = std::fs::read_to_string(&record).unwrap();
    // The runner dies here: no `Drop` runs.
    std::mem::forget(child);
    assert!(
        running("8804").await,
        "control: the member outlived its leader"
    );
    assert!(reap_group(&text), "a surviving member must be reaped");
    assert!(gone("8804").await, "the orphan survived the reap");
    assert!(!reap_group("garbage") && !reap_group("1:x") && !reap_group("0:x"));
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: run scripts/sandbox-macos-test.sh"
)]
async fn a_sandboxed_setsid_child_dies_with_its_session() {
    if !mechanism_available() {
        return;
    }
    let (root, spec) = fixture("setsid");
    let mut cmd = crate::proc::command(
        OsStr::new("/bin/bash"),
        &[
            "-c".into(),
            "perl -MPOSIX -e \'POSIX::setsid(); exec q(sleep), q(8805)\' & echo ready; wait".into(),
        ],
        &spec,
        &[],
    );
    cmd.env("PATH", "/usr/bin:/bin");
    let mut child = Proc::spawn_with_pgid_file(cmd, None).unwrap();
    let _guard = Guard(vec![child.pgid], vec!["8805"]);
    assert_eq!(child.line().await.as_deref(), Some("ready"));
    assert!(running("8805").await, "control: the escapee runs");
    drop(child);
    assert!(gone("8805").await, "a setsid child survived its session");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: run scripts/sandbox-macos-test.sh"
)]
async fn the_watchdog_counts_descendants_that_left_the_group() {
    if !mechanism_available() {
        return;
    }
    let (root, mut spec) = fixture("setsidcount");
    spec.env.retain(|(n, _)| n != "AINKRAD_SANDBOX_PROCESSES");
    spec.env
        .push(("AINKRAD_SANDBOX_PROCESSES".into(), "6".into()));
    // Ten `setsid` sleepers: none is in the leader's group, all must still be counted.
    let mut cmd = crate::proc::command(
        OsStr::new("/bin/bash"),
        &[
            "-c".into(),
            "for i in 1 2 3 4 5 6 7 8 9 10; do perl -MPOSIX -e \'POSIX::setsid(); exec q(sleep), q(8806)\' & done; wait".into(),
        ],
        &spec,
        &[],
    );
    cmd.env("PATH", "/usr/bin:/bin");
    let mut child = Proc::spawn_with_pgid_file(cmd, None).unwrap();
    let _guard = Guard(vec![child.pgid], vec!["8806"]);
    let code = tokio::time::timeout(Duration::from_secs(20), child.wait()).await;
    assert!(
        code.is_ok(),
        "the watchdog never ended an over-limit session"
    );
    assert!(gone("8806").await);
    let _ = std::fs::remove_dir_all(root);
}
