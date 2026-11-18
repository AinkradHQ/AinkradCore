use std::process::Command;

use ainkrad_proto::v2::{PublishedPort, RunLimits, RunPhase, RunStart};

use super::*;

const LIMITS: RunLimits = RunLimits {
    cpus: 0.5,
    memory_mb: 128,
    pids: 128,
};

pub(super) fn start(run: &str, project: u64, spec: serde_json::Value) -> RunStart {
    serde_json::from_value(serde_json::json!({
        "run": run, "project": project, "spec": spec,
        "limits": {"cpus": LIMITS.cpus, "memory_mb": LIMITS.memory_mb, "pids": LIMITS.pids},
    }))
    .unwrap()
}

#[test]
fn create_args_confine_the_container() {
    let s: RunService = serde_json::from_value(serde_json::json!({
        "image": "postgres:17", "repo": "web", "workdir": "/repo/web",
        "volumes": {"data": "/var/lib/postgresql/data"},
        "ports": [{"port": 5432}], "health": {"cmd": "pg_isready"},
        "command": ["postgres", "-c", "fsync=off"]
    }))
    .unwrap();
    let a = create_args(
        "r1",
        7,
        "db",
        &s,
        "postgres:17",
        LIMITS,
        Some(Path::new("/e/r1-db.env")),
        Path::new("/runs/r1"),
    );
    let j = a.join(" ");
    for want in [
        "--network ainkrad-p7 --network-alias db",
        "--label ainkrad.project=7 --label ainkrad.run=r1 --label ainkrad.service=db",
        "--cpus 0.5 --memory 128m --memory-swap 128m --pids-limit 128",
        "--security-opt no-new-privileges",
        "--env-file /e/r1-db.env",
        "-v ainkrad-p7-data:/var/lib/postgresql/data",
        "-v /runs/r1/repos/web:/repo/web:ro",
        "--pull missing",
        "-p 127.0.0.1::5432",
        "--health-cmd pg_isready --health-interval disable",
    ] {
        assert!(j.contains(want), "missing {want} in {j}");
    }
    assert!(j.ends_with("postgres:17 postgres -c fsync=off"), "{j}");
    for never in [
        "--privileged",
        "--network host",
        "--network=host",
        "0.0.0.0",
        "-e ",
    ] {
        assert!(!j.contains(never), "{never} in {j}");
    }
}

/// A git repo at `dir` with `files` (path, contents) and `links` (path, target) committed.
pub(super) fn repo(dir: &Path, files: &[(&str, &[u8])], links: &[(&str, &Path)]) {
    std::fs::create_dir_all(dir).unwrap();
    for (f, body) in files {
        std::fs::create_dir_all(dir.join(f).parent().unwrap()).unwrap();
        std::fs::write(dir.join(f), body).unwrap();
    }
    for (l, target) in links {
        std::os::unix::fs::symlink(target, dir.join(l)).unwrap();
    }
    let git = |args: &[&str]| {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "x"]);
}

/// `git bundle create <to> HEAD` of `dir`.
pub(super) fn bundle(dir: &Path, to: &Path) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["bundle", "create", "-q"])
        .arg(to)
        .arg("HEAD")
        .status()
        .unwrap()
        .success();
    assert!(ok);
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("run-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_build_path_through_a_committed_symlink_is_refused() {
    let d = scratch("inside");
    let outside = d.join("store");
    std::fs::create_dir_all(&outside).unwrap();
    let r = d.join("repo");
    repo(
        &r,
        &[("app/Dockerfile", b"FROM scratch\n")],
        &[("ctx", &outside), ("Dockerfile", &outside.join("x"))],
    );
    let root = r.canonicalize().unwrap();
    assert_eq!(inside(&r, ".").unwrap(), root);
    assert_eq!(
        inside(&r, "app/Dockerfile").unwrap(),
        root.join("app/Dockerfile")
    );
    for bad in ["ctx", "ctx/..", "Dockerfile", "app/../../store", "missing"] {
        assert!(inside(&r, bad).is_err(), "{bad}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn checkouts_past_the_byte_cap_are_refused_before_the_tree_is_written() {
    let d = scratch("cap");
    repo(&d.join("src"), &[("big.bin", &vec![7u8; 3 << 20])], &[]);
    bundle(&d.join("src"), &d.join("b"));
    let engine = |cap| Engine {
        podman: "podman".into(),
        root: d.clone(),
        projects: d.join("projects"),
        networks: d.join("networks"),
        env_dir: d.join("env"),
        runtime_dir: None,
        checkout_cap: cap,
    };
    let later = Instant::now() + Duration::from_secs(60);
    let mut used = 0;
    let why = engine(2 << 20)
        .checkout(&d.join("b"), &d.join("small"), &mut used, later)
        .unwrap_err();
    assert!(why.contains("MiB"), "{why}");
    assert!(!d.join("small/big.bin").exists(), "the tree was written");
    let mut used = 0;
    engine(64 << 20)
        .checkout(&d.join("b"), &d.join("ok"), &mut used, later)
        .unwrap();
    assert_eq!(
        std::fs::metadata(d.join("ok/big.bin")).unwrap().len(),
        3 << 20
    );
    assert!(used >= 3 << 20);
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(target_os = "linux")]
#[test]
fn a_child_past_its_timeout_dies_with_its_whole_group() {
    let d = scratch("timeout");
    let pidfile = d.join("pid");
    let mut c = Command::new("sh");
    c.arg("-c")
        .arg(format!("sleep 60 & echo $! > {}; wait", pidfile.display()));
    let t = Instant::now();
    let why = exec(c, "sh", Duration::from_secs(1)).unwrap_err();
    assert!(why.contains("did not finish"), "{why}");
    assert!(t.elapsed() < Duration::from_secs(10));
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // The grandchild is gone (or a zombie waiting for init), not sleeping on.
    let gone = (0..50).any(|_| {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let dead = stat.is_empty()
            || stat
                .rsplit(')')
                .next()
                .is_some_and(|r| r.trim_start().starts_with('Z'));
        if !dead {
            std::thread::sleep(Duration::from_millis(100));
        }
        dead
    });
    assert!(gone, "the grandchild {pid} outlived the timeout");
    assert_eq!(
        exec(Command::new("true"), "true", Duration::from_secs(5)),
        Ok(String::new())
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ps_output_reads_as_runs_and_a_dead_service_fails_its_run() {
    let ps = r#"[
      {"State":"running","ExitCode":0,"Labels":{"ainkrad.project":"7","ainkrad.run":"r1","ainkrad.service":"db","ainkrad.expose":"5432"},
       "Ports":[{"host_ip":"127.0.0.1","container_port":5432,"host_port":40001,"range":1,"protocol":"tcp"},
                {"host_ip":"0.0.0.0","container_port":9,"host_port":40002,"range":1,"protocol":"tcp"}]},
      {"State":"exited","ExitCode":3,"Labels":{"ainkrad.project":"7","ainkrad.run":"r1","ainkrad.service":"web"}},
      {"State":"running","ExitCode":0,"Labels":{"ainkrad.project":"8","ainkrad.run":"r2","ainkrad.service":"a"}},
      {"State":"created","ExitCode":0,"Labels":{"ainkrad.project":"8","ainkrad.run":"r2","ainkrad.service":"b"}},
      {"State":"running","ExitCode":0,"Labels":{}}
    ]"#;
    let runs = runs_from_ps(ps).unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].phase, RunPhase::Failed);
    assert_eq!(runs[0].failed_service.as_deref(), Some("web"));
    assert!(runs[0].reason.as_deref().unwrap().contains("code 3"));
    assert_eq!(
        runs[0].services[0].ports,
        [PublishedPort {
            port: 5432,
            host_port: 40001,
            expose: true
        }]
    );
    assert_eq!(runs[1].phase, RunPhase::Starting);
    assert_eq!(runs_from_ps("[]").unwrap(), []);
}

// --- On a host with rootless Podman (the run host): `cargo test -p ainkrad-runner run:: -- --ignored`,
// as the user the helper runs as. They pull docker.io alpine:3 and nginx:alpine, and clean up.

pub(super) const ALPINE: &str = "docker.io/library/alpine:3";
const NGINX: &str = "docker.io/library/nginx:alpine";

pub(super) struct Host {
    pub(super) engine: Engine,
    pub(super) tmp: PathBuf,
    projects: Vec<u64>,
    runs: Vec<String>,
}

impl Host {
    pub(super) fn new(name: &str) -> Self {
        let tmp = std::env::temp_dir().join(format!("run-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        Self {
            engine: Engine {
                podman: "podman".into(),
                root: tmp.join("runs"),
                projects: tmp.join("projects"),
                networks: tmp.join("networks"),
                env_dir: tmp.join("env"),
                runtime_dir: None,
                checkout_cap: MAX_CHECKOUT_BYTES,
            },
            tmp,
            projects: Vec::new(),
            runs: Vec::new(),
        }
    }

    /// A project id no one else uses.
    pub(super) fn project(&mut self, n: u64) -> u64 {
        let p = 900_000_000 + u64::from(std::process::id()) * 10 + n;
        self.projects.push(p);
        p
    }

    fn start(&mut self, req: &RunStart) -> RunInfo {
        self.start_with(req, &BTreeMap::new())
    }

    pub(super) fn start_with(
        &mut self,
        req: &RunStart,
        bundles: &BTreeMap<String, PathBuf>,
    ) -> RunInfo {
        self.runs.push(req.run.clone());
        self.engine
            .start(req, bundles, Instant::now() + START_BUDGET)
            .unwrap()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        for r in &self.runs {
            let _ = self.engine.stop(r);
        }
        for p in &self.projects {
            let _ = podman(&self.engine, *p, &["network", "rm", "-f", &network(*p)]);
            let vols = podman(
                &self.engine,
                *p,
                &[
                    "volume",
                    "ls",
                    "-q",
                    "--filter",
                    &format!("label=ainkrad.project={p}"),
                ],
            );
            for v in vols.split_whitespace() {
                let _ = podman(&self.engine, *p, &["volume", "rm", "-f", v]);
            }
            // The project's own store holds files of the user namespace's uids: Podman removes them.
            let _ = podman(&self.engine, *p, &["system", "reset", "-f"]);
        }
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

pub(super) fn podman(e: &Engine, project: u64, args: &[&str]) -> String {
    let o = e.podman_cmd(project, args).output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

/// `sh -c` in a container: whether it exited 0.
fn sh_ok(e: &Engine, project: u64, ctr: &str, script: &str) -> bool {
    e.podman_cmd(project, &["exec", ctr, "sh", "-c", script])
        .status()
        .unwrap()
        .success()
}

#[test]
#[ignore = "needs rootless podman"]
fn a_crashing_service_fails_the_run_and_is_named() {
    let mut h = Host::new("crash");
    let p = h.project(1);
    let id = format!("t{}c", std::process::id());
    // At start: `web` exits at once, after `db` it depends on came up.
    let now = start(
        &format!("{id}1"),
        p,
        serde_json::json!({"services": {
        "db": {"image": ALPINE, "command": ["sleep", "600"]},
        "web": {"image": ALPINE, "command": ["sh", "-c", "exit 3"], "depends_on": ["db"]}}}),
    );
    let r = h.start(&now);
    assert_eq!(
        (r.phase, r.failed_service.as_deref()),
        (RunPhase::Failed, Some("web")),
        "{r:?}"
    );
    // A failed start is stopped: `db`, which did come up, and the run dir are gone.
    assert!(h.engine.status(&now.run, p).unwrap().services.is_empty());
    assert!(!h.engine.root.join(&now.run).exists());
    // Later: `late` runs, then dies; status (labels only, as after a runner restart) names it.
    let later = start(
        &format!("{id}2"),
        p,
        serde_json::json!({"services": {
        "db": {"image": ALPINE, "command": ["sleep", "600"]},
        "late": {"image": ALPINE, "command": ["sh", "-c", "sleep 4; exit 5"]}}}),
    );
    let r = h.start(&later);
    assert_eq!(r.phase, RunPhase::Running, "{r:?}");
    std::thread::sleep(Duration::from_secs(5));
    let r = h.engine.status(&later.run, p).unwrap();
    assert_eq!(
        (r.phase, r.failed_service.as_deref()),
        (RunPhase::Failed, Some("late")),
        "{r:?}"
    );
    assert!(r.reason.unwrap().contains("code 5"));
    // Stop removes the containers.
    assert_eq!(h.engine.stop(&later.run).unwrap().phase, RunPhase::Stopped);
    let r = h.engine.status(&later.run, p).unwrap();
    assert_eq!((r.phase, r.services.len()), (RunPhase::Stopped, 0));
}

#[test]
#[ignore = "needs rootless podman"]
fn the_env_file_is_gone_after_start_and_ports_listen_on_loopback_only() {
    let mut h = Host::new("env");
    let p = h.project(2);
    let run = format!("t{}e", std::process::id());
    let r = h.start(&start(
        &run,
        p,
        serde_json::json!({"services": {"web": {
        "image": NGINX, "env": {"GREETING": "hello-run"},
        "volumes": {"cache": "/var/cache/nginx"},
        "ports": [{"port": 80, "expose": true}],
        "health": {"cmd": "wget -q -O /dev/null http://127.0.0.1/"}}}}),
    ));
    assert_eq!(r.phase, RunPhase::Running, "{r:?}");
    let ctr = container(&run, "web");
    // The env reached the container, and no env file is left behind.
    assert_eq!(
        podman(&h.engine, p, &["exec", &ctr, "printenv", "GREETING"]),
        "hello-run"
    );
    let left: Vec<_> = std::fs::read_dir(&h.engine.env_dir).unwrap().collect();
    assert!(left.is_empty(), "env files left: {left:?}");
    // The memory cap is hard (swap = memory) and the network isolated.
    let mem = podman(
        &h.engine,
        p,
        &[
            "inspect",
            "-f",
            "{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}",
            &ctr,
        ],
    );
    assert_eq!(mem, "134217728 134217728");
    let net = podman(
        &h.engine,
        p,
        &["network", "inspect", "-f", "{{.Options}}", &network(p)],
    );
    assert!(net.contains("isolate:true"), "{net}");
    // Published on 127.0.0.1 only: the host's listener table has it on loopback and nowhere else.
    let hp = r.services[0].ports[0].host_port;
    // Not connected to from here: this test runs as `ainkrad-run`, whose own traffic to the host is
    // refused by the egress table (`fib daddr type local`); the runner, another user, is the client.
    let hex = format!(":{hp:04X} ");
    let tables = std::fs::read_to_string("/proc/net/tcp").unwrap()
        + &std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
    let listeners: Vec<&str> = tables
        .lines()
        .filter(|l| l.contains(&hex) && l.contains(" 0A "))
        .collect();
    assert!(!listeners.is_empty(), "no listener on {hp}");
    for l in listeners {
        let local = l.split_whitespace().nth(1).unwrap();
        assert_eq!(
            local,
            format!("0100007F:{hp:04X}"),
            "off-loopback listener: {l}"
        );
    }
}

#[test]
#[ignore = "needs rootless podman"]
fn a_container_cannot_reach_another_projects_network() {
    let mut h = Host::new("iso");
    let (pa, pb) = (h.project(3), h.project(4));
    let id = std::process::id();
    let spec = serde_json::json!({"services": {
        "web": {"image": NGINX},
        "probe": {"image": ALPINE, "command": ["sleep", "600"], "depends_on": ["web"]}}});
    let a = h.start(&start(&format!("t{id}a"), pa, spec.clone()));
    let b = h.start(&start(&format!("t{id}b"), pb, spec));
    assert_eq!((a.phase, b.phase), (RunPhase::Running, RunPhase::Running));
    let ip = |p: u64, run: &str| {
        podman(
            &h.engine,
            p,
            &[
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                &container(run, "web"),
            ],
        )
    };
    let a_ip = ip(pa, &format!("t{id}a"));
    let (a_probe, b_probe) = (
        container(&format!("t{id}a"), "probe"),
        container(&format!("t{id}b"), "probe"),
    );
    // Inside a project: by service name.
    assert!(sh_ok(
        &h.engine,
        pa,
        &a_probe,
        "wget -T 5 -q -O /dev/null http://web/"
    ));
    assert!(sh_ok(
        &h.engine,
        pa,
        &a_probe,
        &format!("wget -T 5 -q -O /dev/null http://{a_ip}/")
    ));
    // From the other project: not by IP, not by name.
    assert!(!sh_ok(
        &h.engine,
        pb,
        &b_probe,
        &format!("wget -T 5 -q -O /dev/null http://{a_ip}/")
    ));
    let b_web = ip(pb, &format!("t{id}b"));
    assert_ne!(a_ip, b_web);
}

#[test]
#[ignore = "needs rootless podman as ainkrad-run with deploy/run-egress.nft loaded"]
fn the_cloud_metadata_address_and_the_host_itself_are_unreachable() {
    let mut h = Host::new("egress");
    let p = h.project(5);
    let run = format!("t{}m", std::process::id());
    let r = h.start(&start(
        &run,
        p,
        serde_json::json!({"services": {
        "probe": {"image": ALPINE, "command": ["sleep", "600"]}}}),
    ));
    assert_eq!(r.phase, RunPhase::Running);
    let ctr = container(&run, "probe");
    // A TCP connect, not an HTTP answer: the metadata service answers some paths with errors anyway.
    assert!(
        sh_ok(&h.engine, p, &ctr, "nc -w 5 example.com 80 </dev/null"),
        "the internet is reachable"
    );
    assert!(!sh_ok(
        &h.engine,
        p,
        &ctr,
        "nc -w 5 169.254.169.254 80 </dev/null"
    ));
    // The host itself: its own address (the listener is on every address) and the host alias.
    let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let ips = Command::new("hostname").arg("-I").output().unwrap().stdout;
    let host_ip = String::from_utf8_lossy(&ips)
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    for target in [host_ip.as_str(), "host.containers.internal"] {
        assert!(
            !sh_ok(
                &h.engine,
                p,
                &ctr,
                &format!("nc -w 3 {target} {port} </dev/null")
            ),
            "reached the host at {target}:{port}"
        );
    }
}

/// The build context resolves into the image store through a committed symlink: refused, and the
/// whole run cleaned up. A normal build then runs, its checkout mounted read-only, and `stop`
/// removes its image.
#[test]
#[ignore = "needs rootless podman"]
fn builds_stay_in_their_checkout_mount_it_read_only_and_leave_no_image() {
    let mut h = Host::new("build");
    let p = h.project(6);
    let id = std::process::id();
    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    let src = h.tmp.join("src");
    repo(
        &src,
        &[("Dockerfile", format!("FROM {ALPINE}\n").as_bytes())],
        &[("escape", &home.join(".local/share/containers"))],
    );
    let spec = |ctx: &str| {
        let mut r = start(
            &format!("t{id}{}", if ctx == "." { "g" } else { "s" }),
            p,
            serde_json::json!({"services": {
                "db": {"image": ALPINE, "command": ["sleep", "600"]},
                "web": {"build": {"repo": "web", "context": ctx}, "repo": "web",
                        "command": ["sleep", "600"], "depends_on": ["db"]}}}),
        );
        r.checkouts = vec![ainkrad_proto::v2::RunCheckout {
            repo: "web".into(),
            dir: "/unused".into(),
            from_core: None,
        }];
        r
    };
    let tmp = h.tmp.clone();
    let bundles = |n: &str| {
        let b = tmp.join(n);
        bundle(&src, &b);
        BTreeMap::from([("web".to_owned(), b)])
    };
    let escape = spec("escape");
    let b = bundles("b1");
    let r = h.start_with(&escape, &b);
    assert_eq!(
        (r.phase, r.failed_service.as_deref()),
        (RunPhase::Failed, Some("web")),
        "{r:?}"
    );
    assert!(r.reason.unwrap().contains("outside the repo"));
    assert!(h.engine.status(&escape.run, p).unwrap().services.is_empty());
    assert!(!h.engine.root.join(&escape.run).exists());

    let good = spec(".");
    let b = bundles("b2");
    let r = h.start_with(&good, &b);
    assert_eq!(r.phase, RunPhase::Running, "{r:?}");
    let web = container(&good.run, "web");
    assert!(sh_ok(&h.engine, p, &web, "test -f /repo/web/Dockerfile"));
    assert!(
        !sh_ok(&h.engine, p, &web, "touch /repo/web/x"),
        "/repo is writable"
    );
    let tag = format!("localhost/{}-web:{}", network(p), good.run);
    assert!(podman(&h.engine, p, &["images", "-q", &tag]).len() > 1);
    h.engine.stop(&good.run).unwrap();
    assert_eq!(podman(&h.engine, p, &["images", "-q", &tag]), "");
}
