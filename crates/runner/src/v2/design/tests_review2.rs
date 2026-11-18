//! Round-2 security review fixes (PR #303), runner half (Linux, real bubblewrap): job cgroups and
//! `ulimit -u`, the stricter seccomp filter, `design_limit` for a wall-clock stop, and the helper
//! bound alone into the sandbox.
//!
//! The kernel-cap test (`a_job_cgroup_caps_memory_in_the_kernel`) only means something inside the
//! real runner unit (`Delegate=yes`, `ProtectControlGroups=private`); anywhere else it says SKIPPED.
//! Run it there, e.g. as the runner user:
//! `systemd-run --wait --pipe -p User=ainkrad-runner -p Delegate=yes -p ProtectControlGroups=private
//!  -p ProtectHome=yes <test binary> design::tests_review2 --nocapture`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{Command, DesignCheck, ErrorCode, Reply, StreamError};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::oneshot;

use super::cgroup::{Cgroups, enabled};
use super::sandbox::{LIMITS, TASKS_MAX, outcome, sandbox_args};
use super::seccomp::{ALLOW, CLONE_NS, ENOSYS, EPERM, NR, program};
use super::{DesignConfig, DesignDriver, TIME_LIMIT};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "design-r2-{name}-{}-{:?}",
        std::process::id(),
        Instant::now()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A fake helper script `ainkrad-design` in its own directory.
fn helper(name: &str, body: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(name);
    let p = dir.join("ainkrad-design");
    std::fs::write(&p, format!("#!/bin/bash\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    (dir, p)
}

async fn check_with(c: DesignConfig) -> Result<Reply, StreamError> {
    let cmd = Command::DesignCheck(DesignCheck {
        kind: "font".into(),
        data: STANDARD.encode(b"x"),
    });
    let (_keep, rx) = oneshot::channel();
    DesignDriver::new(c).run(&cmd, rx).await
}

fn ok_of(r: Reply) -> (bool, Option<String>) {
    match r {
        Reply::DesignCheck(c) => (c.ok, c.reason),
        other => panic!("{other:?}"),
    }
}

/// Runs the classic BPF filter on one call, as the kernel would: its return value.
fn eval(prog: &[u8], arch: u32, nr: u32, arg0: u64) -> u32 {
    let mut data = [0u8; 64];
    data[..4].copy_from_slice(&nr.to_ne_bytes());
    data[4..8].copy_from_slice(&arch.to_ne_bytes());
    data[16..24].copy_from_slice(&arg0.to_ne_bytes());
    let ins: Vec<(u16, u8, u8, u32)> = prog
        .chunks(8)
        .map(|c| {
            (
                u16::from_ne_bytes([c[0], c[1]]),
                c[2],
                c[3],
                u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
            )
        })
        .collect();
    let (mut pc, mut a) = (0usize, 0u32);
    loop {
        let (code, jt, jf, k) = ins[pc];
        let jump = |t: bool| pc + 1 + usize::from(if t { jt } else { jf });
        pc = match code {
            0x20 => {
                let o = k as usize;
                a = u32::from_ne_bytes(data[o..o + 4].try_into().unwrap());
                pc + 1
            }
            0x15 => jump(a == k),
            0x35 => jump(a >= k),
            0x45 => jump(a & k != 0),
            0x06 => return k,
            other => panic!("unknown op {other:#x}"),
        };
    }
}

#[test]
fn the_filter_narrows_sockets_clone_and_the_new_denials() {
    let p = program().unwrap();
    let arch = eval_arch();
    let run = |nr, arg| eval(&p, arch, nr, arg);
    assert_eq!(run(NR.socket, 1), ALLOW, "AF_UNIX");
    assert_eq!(run(NR.socketpair, 1), ALLOW, "AF_UNIX pair");
    for domain in [2, 10, 16, 17] {
        // AF_INET, AF_INET6, AF_NETLINK, AF_PACKET
        assert_eq!(run(NR.socket, domain), EPERM, "socket {domain}");
        assert_eq!(run(NR.socketpair, domain), EPERM, "socketpair {domain}");
    }
    assert_eq!(run(NR.clone3, 0), ENOSYS);
    // fork (SIGCHLD | CLONE_CHILD_*) and a thread (CLONE_VM | CLONE_THREAD | ...) pass.
    assert_eq!(run(NR.clone, 0x0120_0011), ALLOW);
    assert_eq!(run(NR.clone, 0x003d_0f00), ALLOW);
    for ns in [
        0x0002_0000u32,
        0x0200_0000,
        0x0400_0000,
        0x0800_0000,
        0x1000_0000,
        0x2000_0000,
        0x4000_0000,
    ] {
        assert_ne!(ns & CLONE_NS, 0);
        assert_eq!(run(NR.clone, u64::from(ns | 0x11)), EPERM, "clone {ns:#x}");
    }
    let (personality, kcmp) = if cfg!(target_arch = "x86_64") {
        (135, 312)
    } else {
        (92, 272)
    };
    for nr in [personality, kcmp, 438, 440] {
        assert_eq!(run(nr, 0), EPERM, "{nr}");
    }
    // An ordinary call, and another architecture.
    assert_eq!(run(63, 0), ALLOW);
    assert_eq!(eval(&p, 0x4000_0003, 63, 0), EPERM);
}

fn eval_arch() -> u32 {
    if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else {
        0xc000_00b7
    }
}

/// Inside the real sandbox: a network socket is refused, a Unix one is not, and clone3 answers
/// ENOSYS (so libc falls back to clone, which the filter reads).
#[tokio::test]
async fn the_stricter_filter_holds_inside() {
    let (socket, clone3) = (NR.socket, NR.clone3);
    let body = format!(
        r#"python3 -I -c 'import ctypes,json,socket
l=ctypes.CDLL(None,use_errno=True)
r=[]
s=l.syscall({socket},2,1,0); e=ctypes.get_errno()
if not (s==-1 and e==1): r.append("inet %d %d"%(s,e))
u=l.syscall({socket},1,1,0)
if u<0: r.append("unix %d"%ctypes.get_errno())
c=l.syscall({clone3},0,0); e=ctypes.get_errno()
if not (c==-1 and e==38): r.append("clone3 %d %d"%(c,e))
print(json.dumps({{"ok":not r,"reason":" ".join(r)}}))'"#
    );
    let (dir, p) = helper("filter", &body);
    let mut c = DesignConfig::new(p, None);
    c.timeout = Duration::from_secs(10);
    let (ok, why) = ok_of(check_with(c).await.unwrap());
    assert!(ok, "{why:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_job_has_at_most_256_processes() {
    assert!(LIMITS.contains("ulimit -S -u 256 && ulimit -H -u 256"));
    assert_eq!(TASKS_MAX, 256);
    let (dir, p) = helper(
        "nproc",
        r#"n=$(ulimit -u); h=$(ulimit -H -u); [ "$n" = 256 ] && [ "$h" = 256 ] && echo '{"ok":true}' || echo "{\"ok\":false,\"reason\":\"$n/$h\"}""#,
    );
    let (ok, why) = ok_of(check_with(DesignConfig::new(p, None)).await.unwrap());
    assert!(ok, "ulimit -u is {why:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_wall_clock_stop_is_a_limit_not_a_verdict() {
    let e = outcome(Err(TIME_LIMIT), vec![], b"ainkrad-design: started\n").unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignLimit, "{e:?}");
    let e = outcome(
        Err("it used more memory than allowed"),
        vec![],
        b"ainkrad-design: started\n",
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignFailed, "{e:?}");
}

/// No CPU used, so only the wall clock can stop it: `design_limit`.
#[tokio::test]
async fn a_helper_that_sleeps_past_its_time_is_a_limit() {
    let (dir, p) = helper("sleep", "sleep 30");
    let mut c = DesignConfig::new(p, None);
    c.timeout = Duration::from_secs(1);
    let t = Instant::now();
    let e = check_with(c).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignLimit, "{e:?}");
    assert!(t.elapsed() < Duration::from_secs(10));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn only_the_helper_file_is_bound_not_its_directory() {
    let a = sandbox_args(Path::new("/j"), Some(Path::new("/opt/x/ainkrad-design"))).join(" ");
    assert!(
        a.contains("--ro-bind /opt/x/ainkrad-design /opt/x/ainkrad-design"),
        "{a}"
    );
    assert!(!a.contains("--ro-bind /opt/x /opt/x"), "{a}");
}

#[tokio::test]
async fn a_file_beside_the_helper_is_not_in_the_sandbox() {
    let (dir, p) = helper(
        "beside",
        r#"[ -e "$(dirname "$0")/beside" ] && echo '{"ok":false,"reason":"saw beside"}' || echo '{"ok":true}'"#,
    );
    std::fs::write(dir.join("beside"), "runner state").unwrap();
    let (ok, why) = ok_of(check_with(DesignConfig::new(p, None)).await.unwrap());
    assert!(ok, "{why:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

/// On a plain directory standing in for cgroupfs: the runner's processes move to `runner/`, the
/// controllers are enabled once, and a job child gets its limits.
#[test]
fn a_delegated_subtree_becomes_a_parent_of_job_cgroups() {
    let base = scratch("cgroup");
    std::fs::write(base.join("cgroup.subtree_control"), "").unwrap();
    std::fs::write(base.join("cgroup.procs"), "41\n42\n").unwrap();
    let cg = Cgroups::at(&base).unwrap();
    assert!(base.join("runner/cgroup.procs").exists());
    assert_eq!(
        std::fs::read_to_string(base.join("cgroup.subtree_control")).unwrap(),
        "+memory +pids"
    );
    assert!(enabled("memory pids") && enabled("cpu +memory +pids"));
    assert!(!enabled("memory") && !enabled(""));
    let job = cg.job(1 << 30, TASKS_MAX).unwrap();
    let read = |f: &str| std::fs::read_to_string(job.dir().join(f)).unwrap();
    assert_eq!(read("memory.max"), "1073741824");
    assert_eq!(read("pids.max"), "256");
    assert_eq!(read("memory.swap.max"), "0");
    assert!(job.procs().is_err(), "no cgroup.procs in a fresh plain dir");
    drop(job);
    // A subtree that cannot be read is no subtree.
    assert!(Cgroups::at(&base.join("missing")).is_none());
    let _ = std::fs::remove_dir_all(&base);
}

/// Inside the real runner unit only (see the top of this file).
#[tokio::test]
async fn a_job_cgroup_caps_memory_in_the_kernel() {
    let Some(cg) = Cgroups::delegated() else {
        eprintln!("SKIPPED: not inside the runner unit (no delegated cgroup subtree)");
        return;
    };
    let mut probe = DesignConfig::new(PathBuf::from("/usr/bin/true"), None);
    probe.cgroups = Some(Arc::new(cg));
    assert!(
        super::sandbox::probe(&probe),
        "the sandbox does not start in a job cgroup"
    );
    let (dir, p) = helper(
        "cgmem",
        r#"m=$(head -c 1048576 /dev/zero | tr '\0' a); x=""; while true; do x="$x$m"; done"#,
    );
    let mut c = DesignConfig::new(p, None);
    c.cgroups = probe.cgroups.clone();
    c.timeout = Duration::from_secs(60);
    c.max_rss = 64 << 20;
    c.max_vm = 4 << 30;
    let e = check_with(c).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignFailed, "{e:?}");
    assert!(!e.message.contains("time limit"), "{e:?}");
    std::fs::remove_dir_all(dir).unwrap();
}
