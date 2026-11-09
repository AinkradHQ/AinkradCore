//! Fault injection on the real binaries (E1-14.4), each with an asserted outcome: the Core killed
//! with a command in flight, the runner killed and revoked, the network cut (proxy), a wrong Core
//! at the runner's URL, an expired certificate, a read-only database and a stalled events
//! client. `#[ignore]`d (they wait on real timeouts): `make e1-exit-faults` runs them, one at a
//! time, and each prints a `FAULT <name>:` line with what it measured.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::common::*;
use crate::proxy::Proxy;
use crate::runner::*;

/// A Core behind a proxy, a bootstrapped admin device `a`, and a real runner paired and
/// connected through the proxy.
struct Rig {
    core: Core,
    proxy: Proxy,
    port: u16,
    a: Vec<String>,
    id: String,
    runner: Child,
}

impl Rig {
    fn start(name: &str) -> Self {
        let (port, public) = (free_port(), free_port());
        let core = loopback_core_at(name, port, public);
        let proxy = Proxy::start(public, port);
        let ks = core.keystore("mac");
        bootstrap(&core, &ks);
        let a = args(&[&s(&["--keystore", &ks.display().to_string()]), &core.at()]);
        let id = pair_runner(&core, &a, &format!("http://127.0.0.1:{public}"), "vm");
        let runner = connect(&core, "vm");
        wait_online(&a, &id, true, Duration::from_secs(20));
        Self {
            core,
            proxy,
            port,
            a,
            id,
            runner,
        }
    }

    fn log(&self) -> PathBuf {
        self.core.dir.join("vm.log")
    }

    fn noop(&self) -> std::process::Output {
        ctl(&args(&[&self.a, &s(&["run", "noop", &self.id])]))
    }

    /// The runner process: alive, not a zombie, no children left behind.
    fn runner_healthy(&mut self) {
        assert!(self.runner.try_wait().unwrap().is_none(), "the runner died");
        let pid = self.runner.id().to_string();
        let stat = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid])
            .output()
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&stat.stdout)
                .trim()
                .starts_with('Z')
        );
        let kids = Command::new("pgrep").args(["-P", &pid]).output().unwrap();
        assert!(kids.stdout.is_empty(), "the runner left children");
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self.runner.kill();
        let _ = self.runner.wait();
    }
}

/// `runner.command` audit rows for `id` after `mark`.
fn commands(a: &[String], mark: i64, id: &str) -> Vec<Value> {
    events_after(a, mark)
        .into_iter()
        .filter(|e| {
            e["payload"]["action"] == "runner.command" && e["payload"]["details"]["runner"] == *id
        })
        .collect()
}

fn has_event(a: &[String], mark: i64, kind: &str, id: &str) -> bool {
    events_after(a, mark)
        .iter()
        .any(|e| e["kind"] == kind && e["payload"]["device_id"] == *id)
}

/// The seqs after `mark` are `mark+1..=head`, each once.
fn assert_consecutive(a: &[String], mark: i64) {
    let seqs: Vec<i64> = events_after(a, mark)
        .iter()
        .map(|e| e["seq"].as_i64().unwrap())
        .collect();
    let want: Vec<i64> = (mark + 1..=mark + seqs.len() as i64).collect();
    assert_eq!(seqs, want, "a gap or a duplicate");
}

/// What `path` gained past byte `from`.
fn since(path: &std::path::Path, from: usize) -> String {
    let all = std::fs::read(path).unwrap_or_default();
    String::from_utf8_lossy(all.get(from..).unwrap_or_default()).into_owned()
}

fn len(path: &std::path::Path) -> usize {
    std::fs::metadata(path).map_or(0, |m| m.len() as usize)
}

#[test]
#[ignore = "fault suite: make e1-exit-faults"]
fn core_killed_with_a_command_in_flight() {
    let mut r = Rig::start("f-inflight");
    let mark = head(&r.a);
    r.proxy.hold(true);
    let noop = spawn_ctl(&args(&[&r.a, &s(&["run", "noop", &r.id])]));
    std::thread::sleep(Duration::from_millis(700));
    r.core.kill9();
    let out = noop.wait_with_output().unwrap();
    r.proxy.cut();
    r.proxy.hold(false);
    // The caller gets exactly one answer, a failure: the Core died before the runner's reply.
    assert!(!out.status.success(), "{out:?}");
    let restarted = Instant::now();
    r.core.restart();
    wait_online(&r.a, &r.id, true, Duration::from_secs(60));
    r.runner_healthy();
    assert!(
        commands(&r.a, mark, &r.id).is_empty(),
        "nothing was audited as done"
    );
    assert!(r.noop().status.success());
    assert_eq!(
        commands(&r.a, mark, &r.id).len(),
        1,
        "one row, for the new command"
    );
    eprintln!(
        "FAULT core-kill-in-flight: ctl exit {:?} ({}); Core up + runner back in {:?}; lost command never audited, next noop ok",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).trim(),
        restarted.elapsed()
    );
}

#[test]
#[ignore = "fault suite: make e1-exit-faults"]
fn runner_killed_then_revoked() {
    let mut r = Rig::start("f-runner");
    let mark = head(&r.a);
    r.runner.kill().unwrap();
    r.runner.wait().unwrap();
    let off = wait_online(&r.a, &r.id, false, Duration::from_secs(30));
    wait_event(&r.a, mark, "runner.disconnected", Duration::from_secs(15));
    // The same identity in a new process.
    r.runner = connect(&r.core, "vm");
    let on = wait_online(&r.a, &r.id, true, Duration::from_secs(20));
    assert!(r.noop().status.success());

    let mark = head(&r.a);
    let from = len(&r.log());
    let start = Instant::now();
    let o = ctl(&args(&[&r.a, &s(&["device", "revoke", &r.id])]));
    assert!(o.status.success(), "{o:?}");
    while !has_event(&r.a, mark, "runner.disconnected", &r.id) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the socket stayed open"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let closed = start.elapsed();
    std::thread::sleep(Duration::from_secs(10));
    assert!(
        !has_event(&r.a, mark, "runner.connected", &r.id),
        "a revoked runner came back"
    );
    let ls = stdout(&ctl(&args(&[&r.a, &s(&["runner", "ls"])])));
    assert!(!ls.contains(&r.id), "{ls}");
    let o = r.noop();
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    // It stopped by itself (exit 6) instead of redialing forever.
    let exit = r.runner.try_wait().unwrap().and_then(|s| s.code());
    let redials = since(&r.log(), from).matches("redialing").count();
    assert_eq!(exit, Some(6), "{}", since(&r.log(), from));
    eprintln!(
        "FAULT runner-kill: offline after kill -9 in {off:?}, new process online in {on:?}; \
         revoke closed the socket in {closed:?}, no reconnect in 10 s; runner exit {exit:?}, \
         {redials} redial log lines in 10 s after revocation"
    );
}

#[test]
#[ignore = "fault suite: make e1-exit-faults"]
fn network_cut_mid_command_resumes_once() {
    let mut r = Rig::start("f-cut");
    let mark = head(&r.a);
    let pid = r.runner.id();
    r.proxy.hold(true);
    let noop = spawn_ctl(&args(&[&r.a, &s(&["run", "noop", &r.id])]));
    std::thread::sleep(Duration::from_millis(500));
    let cut = r.proxy.cut();
    r.proxy.hold(false);
    let out = noop.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    // Answered once: done (resumed by seq on the new connection) or reported lost.
    assert!(
        out.status.success() || err.contains("runner_lost"),
        "{out:?}"
    );
    assert_eq!(commands(&r.a, mark, &r.id).len(), 1, "audited exactly once");
    wait_online(&r.a, &r.id, true, Duration::from_secs(30));
    assert_eq!(r.runner.id(), pid);
    r.runner_healthy();
    assert!(r.noop().status.success());
    assert_consecutive(&r.a, mark);
    eprintln!(
        "FAULT network-cut: {cut} sockets cut with a command in flight; ctl {}; one audit row; \
         same runner pid reconnected; events after {mark} consecutive",
        if out.status.success() {
            stdout(&out).trim().to_owned()
        } else {
            err
        }
    );
}

#[test]
#[ignore = "fault suite: make e1-exit-faults"]
fn a_wrong_core_at_the_runners_url_gets_nothing() {
    let mut r = Rig::start("f-wrong-a");
    let from = len(&r.log());
    r.core.kill9();
    // Another Core (another identity) where the runner's URL points.
    let b = loopback_core_at("f-wrong-b", r.port, r.proxy.port);
    let start = Instant::now();
    while !since(&r.log(), from).contains("core_identity_mismatch") {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "{}",
            since(&r.log(), from)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let refused = start.elapsed();
    std::thread::sleep(Duration::from_secs(2));
    let db = b.db.display().to_string();
    let q = |sql: &str| {
        let o = Command::new("sqlite3")
            .args(["-readonly", &db, sql])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    };
    assert_eq!(
        q("SELECT count(*) FROM core_auth_limits"),
        "0",
        "no failed auth reached B"
    );
    let audit = Command::new(server_bin())
        .args(["audit", "export", &db])
        .output()
        .unwrap();
    let audit = String::from_utf8_lossy(&audit.stdout).into_owned();
    assert!(
        !audit.contains(&r.id),
        "B audited nothing of the runner: {audit}"
    );
    assert!(!b.log().contains(&r.id), "B logged nothing of the runner");
    r.runner_healthy();
    eprintln!(
        "FAULT wrong-core: the runner refused Core B in {refused:?} (core_identity_mismatch), \
         B saw no auth attempt and audited/logged nothing of it; {} audit rows on B",
        audit.lines().count()
    );
}
