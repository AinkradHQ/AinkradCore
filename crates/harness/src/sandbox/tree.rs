//! A session's whole process tree, not just its group. A `setsid` child leaves the group,
//! so membership is the group leader's descendants (parent links), its group, and anything
//! seen earlier that is still alive. Killing uses `kill(2)`, never a forked `/bin/kill`, so
//! it still works under pid or memory exhaustion.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub(crate) struct P {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub rss_kb: u64,
    pub cpu_s: f64,
}

/// Every process on the host. Linux reads `/proc` (no fork); macOS has no /proc, so `ps`.
pub(crate) fn snapshot() -> std::io::Result<Vec<P>> {
    if cfg!(target_os = "linux") {
        let mut out = Vec::new();
        for entry in std::fs::read_dir("/proc")?.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue; // exited meanwhile
            };
            let Some((_, rest)) = stat.rsplit_once(')') else {
                continue;
            };
            let f: Vec<&str> = rest.split_whitespace().collect();
            // After the comm: state ppid pgrp session ... utime(11) stime(12) ... rss(21).
            let num = |i: usize| f.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            out.push(P {
                pid,
                ppid: num(1) as u32,
                pgid: num(2) as u32,
                rss_kb: num(21) * 4,
                cpu_s: (num(11) + num(12)) as f64 / 100.0,
            });
        }
        return Ok(out);
    }
    let ps = std::process::Command::new("/bin/ps")
        .args(["-A", "-o", "pid=,ppid=,pgid=,rss=,time="])
        .output()?;
    if !ps.status.success() {
        return Err(std::io::Error::other("ps failed"));
    }
    Ok(String::from_utf8_lossy(&ps.stdout)
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            Some(P {
                pid: c.first()?.parse().ok()?,
                ppid: c.get(1)?.parse().ok()?,
                pgid: c.get(2)?.parse().ok()?,
                rss_kb: c.get(3)?.parse().ok()?,
                cpu_s: super::budget::cpu_seconds(c.get(4)?),
            })
        })
        .collect())
}

/// The pids of one session, shared with the owner so its `Drop` can kill them.
#[derive(Clone)]
pub(crate) struct Tracker {
    root: u32,
    known: Arc<Mutex<HashSet<u32>>>,
}
impl Tracker {
    pub(crate) fn new(root: u32) -> Self {
        Self {
            root,
            known: Arc::new(Mutex::new(HashSet::from([root]))),
        }
    }
    /// Adds new descendants and group members, forgets the dead; returns the live members.
    pub(crate) fn members<'a>(&self, snap: &'a [P]) -> Vec<&'a P> {
        let mut known = self.known.lock().expect("tracker");
        loop {
            let before = known.len();
            for p in snap {
                if p.pid > 1 && (known.contains(&p.ppid) || p.pgid == self.root) {
                    known.insert(p.pid);
                }
            }
            if known.len() == before {
                break;
            }
        }
        let live: HashSet<u32> = snap.iter().map(|p| p.pid).collect();
        known.retain(|p| live.contains(p));
        snap.iter().filter(|p| known.contains(&p.pid)).collect()
    }
    /// SIGKILL to the group and to every pid seen, escapees included.
    pub(crate) fn kill(&self) {
        let _ = ainkrad_sys::killpg(self.root, 9);
        for pid in self.known.lock().expect("tracker").iter() {
            let _ = ainkrad_sys::kill_pid(*pid, 9);
        }
    }
}

/// Whether any live process is in group `pgid`. A group number cannot be reused while a
/// member lives, so this stays safe after the leader is gone.
pub(crate) fn group_alive(pgid: u32) -> bool {
    snapshot().is_ok_and(|s| s.iter().any(|p| p.pgid == pgid))
}

/// macOS has no parent-death signal, so this tiny supervisor lives outside the sandbox and
/// the group and kills the whole tree (escapees included) when `parent` (the runner) dies.
/// Best effort: a child that double-forks and `setsid`s between two 200 ms polls is not seen.
pub(crate) const SUPERVISOR: &str = r#"leader=$1; parent=$2; known=$leader
while :; do
  known=$(/bin/ps -A -o pid=,ppid=,pgid= | /usr/bin/awk -v k="$known" -v l="$leader" 'BEGIN{n=split(k,a," ");for(i=1;i<=n;i++)K[a[i]]=1}{P[NR]=$1;Q[NR]=$2;G[NR]=$3}END{do{c=0;for(i=1;i<=NR;i++)if(!(P[i] in K)&&P[i]>1&&(Q[i] in K||G[i]==l)){K[P[i]]=1;c=1}}while(c);for(i=1;i<=NR;i++)if(P[i] in K)print P[i]}' | /usr/bin/tr '\n' ' ')
  if ! kill -0 "$parent" 2>/dev/null; then kill -KILL $known 2>/dev/null; kill -KILL -- "-$leader" 2>/dev/null; exit 0; fi
  [ -z "$known" ] && exit 0
  sleep 0.2
done"#;

pub(crate) fn supervise(leader: u32, parent: u32) -> std::io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    std::process::Command::new("/bin/bash")
        .args(["-c", SUPERVISOR, "ainkrad-supervisor"])
        .arg(leader.to_string())
        .arg(parent.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
}
