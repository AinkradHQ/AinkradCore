//! What the runner tells the Core about its host in `hello` (`RunnerFacts`): display only.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use ainkrad_proto::v2::{PodmanFacts, RunCaps, RunnerFacts};

/// The first line a command prints, if it ran well.
fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let line = text.lines().next()?.trim();
    (out.status.success() && !line.is_empty()).then(|| line.to_owned())
}

/// `NAME VERSION_ID` of an os-release file, e.g. `Ubuntu 26.04`.
pub(super) fn pretty_from_os_release(text: &str) -> Option<String> {
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_owned())
            .filter(|v| !v.is_empty())
    };
    match (get("NAME"), get("VERSION_ID")) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        _ => get("PRETTY_NAME"),
    }
}

/// The host's own facts, read once per process; `tools` are the harnesses this runner probed.
pub fn gather(
    tools: &BTreeMap<String, String>,
    policy: Option<ainkrad_proto::v2::RunnerPolicy>,
    own_logins: Vec<String>,
) -> RunnerFacts {
    static HOST: OnceLock<(Option<String>, Option<String>, Option<bool>)> = OnceLock::new();
    let (os_pretty, user, root) = HOST.get_or_init(|| {
        let os = if cfg!(target_os = "macos") {
            run("sw_vers", &["-productVersion"]).map(|v| format!("macOS {v}"))
        } else {
            std::fs::read_to_string("/etc/os-release")
                .ok()
                .and_then(|t| pretty_from_os_release(&t))
        };
        let uid = run("id", &["-u"]);
        (os, run("id", &["-un"]), uid.map(|u| u == "0"))
    });
    let podman = podman_facts(
        Path::new("/"),
        run("podman", &["--version"]).and_then(|l| super::tools::version_of(&l)),
    );
    RunnerFacts {
        os_pretty: os_pretty.clone(),
        user: user.clone(),
        root: *root,
        // What the host has installed (probed now), with the harnesses the agent driver proved.
        tools: {
            let mut all = super::tools::probe_tools();
            all.extend(tools.clone());
            all
        },
        own_logins,
        policy,
        podman: podman.clone(),
        run_caps: run_caps(podman.as_ref(), Path::new("/"), host_resources()),
    }
}

/// The user project containers run as (`deploy/install-linux.sh --with-run`).
const RUN_USER: &str = "ainkrad-run";

/// `1.2.3`'s major.
fn major(version: &str) -> u32 {
    version
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or(0)
}

/// Podman, and whether the rootless setup of [`RUN_USER`] under `root` is complete: the user, a
/// subuid and a subgid range, and linger (the user manager that enforces the limits). All read from
/// files, because the unprivileged runner cannot run podman as that user.
pub(super) fn podman_facts(root: &Path, version: Option<String>) -> Option<PodmanFacts> {
    let version = version?;
    let has = |f: &str| {
        std::fs::read_to_string(root.join(f))
            .is_ok_and(|t| t.lines().any(|l| l.starts_with(&format!("{RUN_USER}:"))))
    };
    let rootless = has("etc/passwd")
        && has("etc/subuid")
        && has("etc/subgid")
        && root.join("var/lib/systemd/linger").join(RUN_USER).exists();
    Some(PodmanFacts { version, rootless })
}

/// `cpu`, `memory` and `pids` are delegated to [`RUN_USER`]'s manager: without them `--cpus` or
/// `--memory` would be ignored.
fn delegated(root: &Path) -> bool {
    let uid = std::fs::read_to_string(root.join("etc/passwd"))
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                let mut f = l.split(':');
                (f.next()? == RUN_USER).then(|| f.nth(1)?.parse::<u32>().ok())?
            })
        });
    let Some(uid) = uid else { return false };
    let path = root.join(format!(
        "sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers"
    ));
    std::fs::read_to_string(path).is_ok_and(|t| {
        ["cpu", "memory", "pids"]
            .iter()
            .all(|c| t.split_whitespace().any(|w| w == *c))
    })
}

/// `(cpus, mem_mb)` of this host.
fn host_resources() -> (u32, u64) {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    let kb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("MemTotal:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        })
        .unwrap_or(0);
    (cpus, kb / 1024)
}

/// Present only when project runs are safe here (see `RunnerFacts::run_caps`).
pub(super) fn run_caps(
    podman: Option<&PodmanFacts>,
    root: &Path,
    (cpus, mem_mb): (u32, u64),
) -> Option<RunCaps> {
    let p = podman.filter(|p| p.rootless)?;
    // ponytail: `isolate` is read from the Podman version (5+ ships a netavark that has it), not
    // proven by creating a network; probe with a throwaway network if a distro ever breaks that.
    delegated(root).then_some(RunCaps {
        cpus,
        mem_mb,
        isolate: major(&p.version) >= 5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_reads_as_name_and_version() {
        let t = "PRETTY_NAME=\"Ubuntu 26.04 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\n";
        assert_eq!(pretty_from_os_release(t).as_deref(), Some("Ubuntu 26.04"));
        assert_eq!(
            pretty_from_os_release("PRETTY_NAME=Arch").as_deref(),
            Some("Arch")
        );
        assert_eq!(pretty_from_os_release(""), None);
    }

    #[test]
    fn a_harness_with_a_login_file_is_an_own_login_and_reaches_the_facts() {
        let root = std::env::temp_dir().join(format!("own-logins-{}", std::process::id()));
        std::fs::create_dir_all(root.join("claude")).unwrap();
        std::fs::create_dir_all(root.join("codex")).unwrap();
        std::fs::write(root.join("claude/.credentials.json"), "{}").unwrap();
        let found = crate::state::logins(
            &root,
            &root.join("credentials"),
            ["claude", "codex"].into_iter(),
        );
        let own = super::super::agent::own_logins(found);
        assert_eq!(own, ["claude"]);
        let facts = gather(&BTreeMap::new(), None, own);
        assert_eq!(facts.own_logins, ["claude"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A fake host tree; `drop` leaves one prerequisite out.
    fn host(name: &str, drop: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("run-caps-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let w = |f: &str, t: &str| {
            let p = root.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, t).unwrap();
        };
        if drop != "passwd" {
            w(
                "etc/passwd",
                "root:x:0:0::/root:/bin/sh\nainkrad-run:x:985:985::/var/lib/ainkrad-run:/usr/sbin/nologin\n",
            );
        }
        if drop != "subuid" {
            w(
                "etc/subuid",
                "ahmed:100000:65536\nainkrad-run:300000:65536\n",
            );
        }
        if drop != "subgid" {
            w("etc/subgid", "ainkrad-run:300000:65536\n");
        }
        if drop != "linger" {
            w("var/lib/systemd/linger/ainkrad-run", "");
        }
        let ctl = if drop == "cpu" {
            "memory pids"
        } else {
            "cpu memory pids"
        };
        w(
            "sys/fs/cgroup/user.slice/user-985.slice/user@985.service/cgroup.controllers",
            ctl,
        );
        root
    }

    #[test]
    fn run_caps_need_every_prerequisite_and_name_the_host() {
        let ok = host("ok", "");
        let p = podman_facts(&ok, Some("5.7.0".into()));
        assert_eq!(
            p,
            Some(PodmanFacts {
                version: "5.7.0".into(),
                rootless: true
            })
        );
        assert_eq!(
            run_caps(p.as_ref(), &ok, (2, 11900)),
            Some(RunCaps {
                cpus: 2,
                mem_mb: 11900,
                isolate: true
            })
        );
        // Each missing prerequisite: podman stays reported, run_caps goes.
        for gone in ["passwd", "subuid", "subgid", "linger"] {
            let r = host(gone, gone);
            let p = podman_facts(&r, Some("5.7.0".into()));
            assert_eq!(p.as_ref().map(|p| p.rootless), Some(false), "{gone}");
            assert_eq!(run_caps(p.as_ref(), &r, (2, 1)), None, "{gone}");
        }
        // Rootless is complete but cpu is not delegated (older systemd without the drop-in).
        let r = host("cpu", "cpu");
        let p = podman_facts(&r, Some("5.7.0".into()));
        assert_eq!(p.as_ref().map(|p| p.rootless), Some(true));
        assert_eq!(run_caps(p.as_ref(), &r, (2, 1)), None);
        // No podman at all; an old podman has no isolate networks.
        assert_eq!(podman_facts(&ok, None), None);
        let old = podman_facts(&ok, Some("4.9.3".into()));
        assert!(!run_caps(old.as_ref(), &ok, (2, 1)).unwrap().isolate);
        for n in ["ok", "passwd", "subuid", "subgid", "linger", "cpu"] {
            let _ = std::fs::remove_dir_all(
                std::env::temp_dir().join(format!("run-caps-{n}-{}", std::process::id())),
            );
        }
    }

    #[test]
    fn the_facts_serialise_without_podman_when_it_is_absent() {
        let j = serde_json::to_value(RunnerFacts::default()).unwrap();
        assert!(j.get("podman").is_none() && j.get("run_caps").is_none());
        let back: RunnerFacts = serde_json::from_str("{}").unwrap();
        assert_eq!(back, RunnerFacts::default());
    }
}
