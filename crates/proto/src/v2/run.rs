//! The `run` driver's ops (Core 0.9 Projects, P5-02, plan T3/T5/T7): a runner starts, stops and
//! reports a project's services as rootless Podman containers.
//!
//! The spec is the project's run spec (P4-01, the same JSON); the Core validated it on save and the
//! runner checks it again here ([`RunStart::problem`]) before any of it becomes a `podman` argument,
//! so a value can never be read as a flag or a host path. Secrets travel as leases the runner
//! redeems itself, never as values.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const DRIVER_RUN: &str = "run";
pub const OP_RUN_START: &str = "run.start";
pub const OP_RUN_STOP: &str = "run.stop";
pub const OP_RUN_STATUS: &str = "run.status";

/// A project's run spec: its services by name (P4-01's `RunSpec`, as JSON).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunSpec {
    pub services: BTreeMap<String, RunService>,
}

/// One container: an `image` or a `build`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunService {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<RunBuild>,
    /// Mount this repo's checkout at `/repo/<name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Plain values, or values with `${secret:NAME}` that the runner fills from `RunStart::secrets`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Volume name to the container path it is mounted at; the volume is `ainkrad-p<project>-<name>`.
    #[serde(default)]
    pub volumes: BTreeMap<String, String>,
    #[serde(default)]
    pub ports: Vec<RunPort>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<RunHealth>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunBuild {
    pub repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunPort {
    /// The container port; published on the runner's loopback only, at a port Podman picks.
    pub port: u16,
    #[serde(default)]
    pub expose: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunHealth {
    /// Run in the container by its shell; exit 0 is healthy.
    pub cmd: String,
}

/// The project's caps, applied to every container of the run.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunLimits {
    pub cpus: f64,
    pub memory_mb: u64,
    pub pids: u32,
}

/// A repo checkout the runner prepared for this run (P3-02's clone from the Core copy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunCheckout {
    pub repo: String,
    /// Absolute path of the checkout on the runner host.
    pub dir: String,
}

/// A secret the spec names, as a lease (`l_…`) the runner redeems once.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunSecret {
    pub name: String,
    pub lease: String,
}

/// Not derived: no log line may carry a lease.
impl std::fmt::Debug for RunSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunSecret")
            .field("name", &self.name)
            .field("lease", &"[hidden]")
            .finish()
    }
}

/// Starts run `run` of project `project`: network, volumes, checkouts, builds, then the services
/// in `depends_on` order. Answers `run.start` with the run's [`RunInfo`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunStart {
    pub run: String,
    pub project: u64,
    pub spec: RunSpec,
    pub limits: RunLimits,
    #[serde(default)]
    pub checkouts: Vec<RunCheckout>,
    #[serde(default)]
    pub secrets: Vec<RunSecret>,
}

/// Stops a run: `podman stop -t 10`, then its containers are removed; volumes stay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunStop {
    pub run: String,
}

/// One run's state, or (no `run`) every run on the runner, read from container labels.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunStatusReq {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunPhase {
    Starting,
    Running,
    /// No container of the run is left.
    Stopped,
    /// A service is not running (`failed_service`).
    Failed,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PublishedPort {
    pub port: u16,
    /// Where it listens on the runner's 127.0.0.1.
    pub host_port: u16,
    /// The spec marked it `expose: true`: the only ports `port.open` serves (P6-01).
    #[serde(default)]
    pub expose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServiceStatus {
    pub name: String,
    /// Podman's state: `created`, `running`, `exited`, ...
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PublishedPort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunInfo {
    pub run: String,
    pub project: u64,
    pub phase: RunPhase,
    /// With `failed`: the service that is not running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_service: Option<String>,
    /// With `failed`: why, in words (redacted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub services: Vec<ServiceStatus>,
}

/// The answer to `run.status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunList {
    pub runs: Vec<RunInfo>,
}

/// A run id: 1-40 of `a-z0-9_-` (it is part of container names).
pub fn valid_run_id(r: &str) -> bool {
    (1..=40).contains(&r.len())
        && r.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
}

/// A service, repo or volume name: 1-40 of `a-z0-9_-`, starting with a letter or digit.
fn valid_name(n: &str) -> bool {
    valid_run_id(n) && n.as_bytes()[0].is_ascii_alphanumeric()
}

/// Absolute, no `..`/`.`/empty parts, and none of the characters Podman's `-v` and `--mount`
/// syntax gives a meaning (`:` and `,`).
fn container_path_ok(p: &str) -> bool {
    p.len() <= 255
        && p.starts_with('/')
        && !p.contains([':', ',', '\0', '\n', '\r'])
        && p[1..].split('/').all(|c| !matches!(c, "" | "." | ".."))
}

/// Relative inside a repo, no `..`; `.` alone when `dot_ok`.
fn repo_path_ok(p: &str, dot_ok: bool) -> bool {
    (p == "." && dot_ok)
        || (p.len() <= 255
            && !p.starts_with('/')
            && !p.contains(['\0', '\n', '\r'])
            && p.split('/').all(|c| !matches!(c, "" | "." | "..")))
}

/// Image transports Podman reads instead of a registry (`oci-archive:/path`, `dir:x`, ...).
const TRANSPORTS: &[&str] = &[
    "containers-storage",
    "dir",
    "docker",
    "docker-archive",
    "docker-daemon",
    "oci",
    "oci-archive",
    "ostree",
    "sif",
    "tarball",
];

/// Printable ASCII, not a flag, and a registry image: never a transport, a `localhost/` image, an
/// image id, or one of the run helper's own build tags (`ainkrad-p...`), which would read another
/// project's build out of the shared image store. The full grammar is the Core's (P4-01).
pub fn image_ok(i: &str) -> bool {
    let l = i.to_ascii_lowercase();
    let first = l.split(['/', '@']).next().unwrap_or("");
    // `docker:27-dind` is a registry image (that transport needs `docker://`).
    let transport = first
        .split_once(':')
        .is_some_and(|(t, rest)| TRANSPORTS.contains(&t) && (t != "docker" || rest.is_empty()));
    let id = !l.contains(['/', ':', '@']) && l.bytes().all(|b| b.is_ascii_hexdigit());
    (1..=255).contains(&i.len())
        && !i.starts_with('-')
        && i.bytes().all(|b| b.is_ascii_graphic())
        && !transport
        && !id
        && !l.starts_with("sha256:")
        && first != "localhost"
        && !first.starts_with("localhost:")
        && !l.contains("ainkrad-p")
}

impl RunStart {
    /// What is wrong with the request, if anything, as `path: why`.
    pub fn problem(&self) -> Option<String> {
        let bad = |at: &str, why: &str| Some(format!("{at}: {why}"));
        if !valid_run_id(&self.run) {
            return bad("run", "1-40 of a-z, 0-9, _ and -");
        }
        let l = self.limits;
        if !(l.cpus > 0.0 && l.cpus <= 64.0) || !(16..=1 << 20).contains(&l.memory_mb) {
            return bad("limits", "cpus in (0, 64], memory_mb 16 to 1048576");
        }
        if !(16..=32768).contains(&l.pids) {
            return bad("limits.pids", "16 to 32768");
        }
        if self.checkouts.len() > 16 {
            return bad("checkouts", "at most 16");
        }
        for (i, c) in self.checkouts.iter().enumerate() {
            if !valid_name(&c.repo) || !c.dir.starts_with('/') {
                return bad("checkouts", "a repo name and an absolute dir");
            }
            if self.checkouts[..i].iter().any(|o| o.repo == c.repo) {
                return bad("checkouts", "one checkout per repo");
            }
        }
        let has_repo = |r: &str| self.checkouts.iter().any(|c| c.repo == r);
        let n = self.spec.services.len();
        if !(1..=16).contains(&n) {
            return bad("spec.services", "1 to 16 services");
        }
        for (name, s) in &self.spec.services {
            let at = format!("spec.services.{name}");
            if !valid_name(name) {
                return bad(&at, "a service name is 1-40 of a-z, 0-9, _ and -");
            }
            match (&s.image, &s.build) {
                (Some(i), None) if image_ok(i) => {}
                (None, Some(b)) if has_repo(&b.repo) => {
                    let paths = [(&b.dockerfile, false), (&b.context, true)];
                    if paths
                        .iter()
                        .any(|(p, dot)| p.as_deref().is_some_and(|p| !repo_path_ok(p, *dot)))
                    {
                        return bad(&at, "build paths are relative, inside the repo");
                    }
                }
                _ => return bad(&at, "one valid image, or a build from a checked-out repo"),
            }
            if s.repo.as_deref().is_some_and(|r| !has_repo(r)) {
                return bad(&format!("{at}.repo"), "not among the checkouts");
            }
            if s.workdir.as_deref().is_some_and(|w| !container_path_ok(w)) {
                return bad(&format!("{at}.workdir"), "an absolute container path");
            }
            if s.command
                .as_ref()
                .is_some_and(|c| c.is_empty() || c.len() > 64)
            {
                return bad(&format!("{at}.command"), "1 to 64 arguments");
            }
            for (k, v) in &s.env {
                let b = k.as_bytes();
                let name_ok = (1..=128).contains(&b.len())
                    && (b[0].is_ascii_alphabetic() || b[0] == b'_')
                    && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
                // An env file holds one variable per line.
                if !name_ok || v.contains(['\n', '\r', '\0']) {
                    return bad(&format!("{at}.env.{k}"), "a name and a one-line value");
                }
            }
            for (v, p) in &s.volumes {
                if !valid_name(v)
                    || !container_path_ok(p)
                    || p == "/repo"
                    || p.starts_with("/repo/")
                {
                    return bad(
                        &format!("{at}.volumes.{v}"),
                        "a volume name and a container path",
                    );
                }
            }
            if s.ports.len() > 8 || s.ports.iter().any(|p| p.port == 0) {
                return bad(&format!("{at}.ports"), "at most 8 ports of 1-65535");
            }
            if s.health.as_ref().is_some_and(|h| {
                h.cmd.is_empty() || h.cmd.len() > 512 || h.cmd.contains(['\n', '\r', '\0'])
            }) {
                return bad(&format!("{at}.health.cmd"), "one line of 1-512 characters");
            }
            if let Some(d) = s
                .depends_on
                .iter()
                .find(|d| !self.spec.services.contains_key(*d))
            {
                return bad(&format!("{at}.depends_on"), &format!("no service {d}"));
            }
        }
        match self.spec.start_order() {
            Some(_) => None,
            None => bad("spec.services", "a depends_on cycle"),
        }
    }
}

impl RunSpec {
    /// Service names, each after everything it depends on; `None` on a cycle.
    pub fn start_order(&self) -> Option<Vec<&str>> {
        let mut out: Vec<&str> = Vec::new();
        while out.len() < self.services.len() {
            let next = self.services.iter().find(|(n, s)| {
                !out.contains(&n.as_str()) && s.depends_on.iter().all(|d| out.contains(&d.as_str()))
            })?;
            out.push(next.0);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(spec: serde_json::Value) -> RunStart {
        serde_json::from_value(serde_json::json!({
            "run": "r1", "project": 7, "spec": spec,
            "limits": {"cpus": 1.0, "memory_mb": 256, "pids": 256},
            "checkouts": [{"repo": "web", "dir": "/w/web"}],
        }))
        .unwrap()
    }

    #[test]
    fn a_good_start_passes_and_orders_by_depends_on() {
        let s = start(serde_json::json!({"services": {
            "web": {"build": {"repo": "web"}, "repo": "web", "depends_on": ["db"],
                    "ports": [{"port": 3000, "expose": true}], "env": {"A": "${secret:x}"}},
            "db": {"image": "postgres:17", "volumes": {"data": "/var/lib/postgresql/data"},
                   "health": {"cmd": "pg_isready"}}}}));
        assert_eq!(s.problem(), None);
        assert_eq!(s.spec.start_order().unwrap(), ["db", "web"]);
    }

    #[test]
    fn flags_host_paths_cycles_and_bad_names_are_refused() {
        let bad = [
            serde_json::json!({"services": {"a": {"image": "--privileged"}}}),
            serde_json::json!({"services": {"a": {"image": "x y"}}}),
            serde_json::json!({"services": {"a": {"image": "x", "volumes": {"v": "/a:/b"}}}}),
            serde_json::json!({"services": {"a": {"image": "x", "volumes": {"/etc": "/b"}}}}),
            serde_json::json!({"services": {"a": {"image": "x", "volumes": {"v": "/repo/web"}}}}),
            serde_json::json!({"services": {"a": {"image": "x", "workdir": "rel"}}}),
            serde_json::json!({"services": {"a": {"image": "x", "repo": "other"}}}),
            serde_json::json!({"services": {"a": {"build": {"repo": "web", "context": "../.."}}}}),
            serde_json::json!({"services": {"a": {"image": "x", "env": {"A": "1\nB=2"}}}}),
            serde_json::json!({"services": {"A": {"image": "x"}}}),
            serde_json::json!({"services": {
                "a": {"image": "x", "depends_on": ["b"]}, "b": {"image": "x", "depends_on": ["a"]}}}),
            serde_json::json!({"services": {}}),
            // Only the run helper's own builds may be local images.
            serde_json::json!({"services": {"a": {"image": "localhost/ainkrad-p8-web:r2"}}}),
            serde_json::json!({"services": {"a": {"image": "localhost:5000/x"}}}),
            serde_json::json!({"services": {"a": {"image": "ainkrad-p8-web:r2"}}}),
            serde_json::json!({"services": {"a": {"image": "docker.io/x/AINKRAD-P8-web"}}}),
            serde_json::json!({"services": {"a": {"image": "oci-archive:/var/lib/x.tar"}}}),
            serde_json::json!({"services": {"a": {"image": "dir:/tmp/x"}}}),
            serde_json::json!({"services": {"a": {"image": "docker-archive:x.tar"}}}),
            serde_json::json!({"services": {"a": {"image": "containers-storage:alpine"}}}),
            serde_json::json!({"services": {"a": {"image": "docker://alpine"}}}),
            serde_json::json!({"services": {"a": {"image": "sha256:0759823471bf"}}}),
            serde_json::json!({"services": {"a": {"image": "0759823471bf"}}}),
        ];
        for spec in bad {
            assert!(start(spec.clone()).problem().is_some(), "accepted {spec}");
        }
        let mut s = start(serde_json::json!({"services": {"a": {"image": "x"}}}));
        s.run = "../x".into();
        assert!(s.problem().is_some());
        s.run = "r1".into();
        s.limits.memory_mb = 0;
        assert!(s.problem().is_some());
    }

    #[test]
    fn registry_images_pass_and_checkouts_are_capped() {
        for ok in [
            "alpine",
            "alpine:3",
            "docker:27-dind",
            "docker.io/library/nginx:alpine",
            "ghcr.io/o/app@sha256:0759823471bf",
            "registry.example:5000/team/app:1.2",
        ] {
            assert!(image_ok(ok), "{ok}");
        }
        let mut s = start(serde_json::json!({"services": {"a": {"image": "x"}}}));
        s.checkouts.push(s.checkouts[0].clone());
        assert!(s.problem().unwrap().contains("one checkout per repo"));
        s.checkouts = (0..17)
            .map(|i| RunCheckout {
                repo: format!("r{i}"),
                dir: "/w".into(),
            })
            .collect();
        assert!(s.problem().unwrap().contains("at most 16"));
    }

    #[test]
    fn a_secret_lease_never_prints() {
        let s = RunSecret {
            name: "db".into(),
            lease: "l_secret".into(),
        };
        assert!(!format!("{s:?}").contains("l_secret"));
    }
}
