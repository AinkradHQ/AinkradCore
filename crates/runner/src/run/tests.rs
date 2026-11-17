use std::process::Command;

use ainkrad_proto::v2::{RunLimits, RunPhase, RunStart};

use super::*;

const LIMITS: RunLimits = RunLimits {
    cpus: 0.5,
    memory_mb: 128,
    pids: 128,
};

fn start(run: &str, project: u64, spec: serde_json::Value) -> RunStart {
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
        "-v /runs/r1/repos/web:/repo/web",
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

#[test]
fn ps_output_reads_as_runs_and_a_dead_service_fails_its_run() {
    let ps = r#"[
      {"State":"running","ExitCode":0,"Labels":{"ainkrad.project":"7","ainkrad.run":"r1","ainkrad.service":"db"},
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
            host_port: 40001
        }]
    );
    assert_eq!(runs[1].phase, RunPhase::Starting);
    assert_eq!(runs_from_ps("[]").unwrap(), []);
}

// --- On a host with rootless Podman (the run host): `cargo test -p ainkrad-runner run:: -- --ignored`,
// as the user the helper runs as. They pull docker.io alpine:3 and nginx:alpine, and clean up.

const ALPINE: &str = "docker.io/library/alpine:3";
const NGINX: &str = "docker.io/library/nginx:alpine";

struct Host {
    engine: Engine,
    tmp: PathBuf,
    projects: Vec<u64>,
    runs: Vec<String>,
}

impl Host {
    fn new(name: &str) -> Self {
        let tmp = std::env::temp_dir().join(format!("run-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        Self {
            engine: Engine {
                podman: "podman".into(),
                root: tmp.join("runs"),
                env_dir: tmp.join("env"),
                runtime_dir: None,
            },
            tmp,
            projects: Vec::new(),
            runs: Vec::new(),
        }
    }

    /// A project id no one else uses.
    fn project(&mut self, n: u64) -> u64 {
        let p = 900_000_000 + u64::from(std::process::id()) * 10 + n;
        self.projects.push(p);
        p
    }

    fn start(&mut self, req: &RunStart) -> RunInfo {
        self.runs.push(req.run.clone());
        self.engine.start(req, &BTreeMap::new()).unwrap()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        for r in &self.runs {
            let _ = self.engine.stop(r);
        }
        for p in &self.projects {
            let _ = podman(&["network", "rm", "-f", &network(*p)]);
            let vols = podman(&[
                "volume",
                "ls",
                "-q",
                "--filter",
                &format!("label=ainkrad.project={p}"),
            ]);
            for v in vols.split_whitespace() {
                let _ = podman(&["volume", "rm", "-f", v]);
            }
        }
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

fn podman(args: &[&str]) -> String {
    let o = Command::new("podman").args(args).output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

/// `sh -c` in a container: whether it exited 0.
fn sh_ok(ctr: &str, script: &str) -> bool {
    Command::new("podman")
        .args(["exec", ctr, "sh", "-c", script])
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
    assert_eq!(podman(&["exec", &ctr, "printenv", "GREETING"]), "hello-run");
    let left: Vec<_> = std::fs::read_dir(&h.engine.env_dir).unwrap().collect();
    assert!(left.is_empty(), "env files left: {left:?}");
    // The memory cap is hard (swap = memory) and the network isolated.
    let mem = podman(&[
        "inspect",
        "-f",
        "{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}",
        &ctr,
    ]);
    assert_eq!(mem, "134217728 134217728");
    let net = podman(&["network", "inspect", "-f", "{{.Options}}", &network(p)]);
    assert!(net.contains("isolate:true"), "{net}");
    // Published on 127.0.0.1 only: the host's listener table has it on loopback and nowhere else.
    let hp = r.services[0].ports[0].host_port;
    assert!(std::net::TcpStream::connect(("127.0.0.1", hp)).is_ok());
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
    let ip = |run: &str| {
        podman(&[
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &container(run, "web"),
        ])
    };
    let a_ip = ip(&format!("t{id}a"));
    let (a_probe, b_probe) = (
        container(&format!("t{id}a"), "probe"),
        container(&format!("t{id}b"), "probe"),
    );
    // Inside a project: by service name.
    assert!(sh_ok(&a_probe, "wget -T 5 -q -O /dev/null http://web/"));
    assert!(sh_ok(
        &a_probe,
        &format!("wget -T 5 -q -O /dev/null http://{a_ip}/")
    ));
    // From the other project: not by IP, not by name.
    assert!(!sh_ok(
        &b_probe,
        &format!("wget -T 5 -q -O /dev/null http://{a_ip}/")
    ));
    let b_web = ip(&format!("t{id}b"));
    assert_ne!(a_ip, b_web);
}

#[test]
#[ignore = "needs rootless podman as ainkrad-run with deploy/run-egress.nft loaded"]
fn the_cloud_metadata_address_is_unreachable() {
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
        sh_ok(&ctr, "nc -w 5 example.com 80 </dev/null"),
        "the internet is reachable"
    );
    assert!(!sh_ok(&ctr, "nc -w 5 169.254.169.254 80 </dev/null"));
}
