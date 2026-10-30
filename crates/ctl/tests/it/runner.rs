//! `runner ls|show` and `run noop` against the real binaries (E1-14.2): a real `ainkrad-runner`
//! pairs (approved by ctl with the SAS the runner printed) and connects over loopback to a real
//! `ainkrad-core-server`; ctl sees it online, runs the no-op, sees the `runner.*` events in
//! `events tail`, and sees it go offline when the runner is killed.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::common::*;

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A Core on `loopback:<port>`; ctl talks to it over its admin socket (`--host 127.0.0.1:<port>`).
pub fn loopback_core(name: &str) -> (Core, String) {
    let port = free_port();
    let core = loopback_core_at(name, port, port);
    (core, format!("http://127.0.0.1:{port}"))
}

/// A Core on `loopback:<port>` that answers to `127.0.0.1:<public>` (a proxy's port).
pub fn loopback_core_at(name: &str, port: u16, public: u16) -> Core {
    let dir = std::env::temp_dir().join(format!("ctl-{name}-{}", std::process::id()));
    let host = format!("127.0.0.1:{public}");
    // The runner dials plain loopback, allowed only by the flag (security review RH2).
    let listen = s(&[
        "--listen",
        &format!("loopback:{port}"),
        "--host",
        &host,
        "--allow-plain-runner",
    ]);
    Core::start_with(
        dir.clone(),
        dir.join("admin.sock"),
        listen,
        Some(host),
        |_| {},
    )
}

/// Pairs a real runner as `name` through ctl (`base`: an admin device); its device id.
pub fn pair_runner(core: &Core, base: &[String], url: &str, name: &str) -> String {
    let o = ctl(&args(&[
        base,
        &s(&["device", "add", name, "--kind", "runner"]),
    ]));
    assert!(o.status.success(), "{o:?}");
    let out = stdout(&o);
    let (pairing, code) = (
        field(&out, "pairing_id").unwrap(),
        field(&out, "code").unwrap(),
    );
    let state = core.dir.join(name);
    let mut pair = Command::new(runner_bin())
        .args(["pair", url, "--code", &code, "--state"])
        .arg(&state)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = Lines::of(pair.stdout.take().unwrap());
    // "Claimed. …" then the SAS on its own indented line.
    let sas = loop {
        let l = lines
            .next(Duration::from_secs(20))
            .expect("the runner shows a SAS");
        let t = l.trim();
        if l.starts_with(' ') && t.len() == 19 {
            break t.to_owned();
        }
    };
    let ok = ctl(&args(&[base, &s(&["device", "approve", &pairing, &sas])]));
    assert!(ok.status.success(), "{ok:?}");
    let done = lines.next(Duration::from_secs(20)).unwrap_or_default();
    assert!(pair.wait().unwrap().success(), "{}", lines.seen);
    done.strip_prefix("Paired as ")
        .and_then(|r| r.split(' ').next())
        .unwrap_or_else(|| panic!("{}", lines.seen))
        .to_owned()
}

/// `ainkrad-runner connect` for the runner paired as `name`; stderr in `<name>.log`.
pub fn connect(core: &Core, name: &str) -> Child {
    let log = std::fs::File::create(core.dir.join(format!("{name}.log"))).unwrap();
    Command::new(runner_bin())
        .args(["connect", "--state"])
        .arg(core.dir.join(name))
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap()
}

/// `runner show <id> --json`.
pub fn show(base: &[String], id: &str) -> Value {
    let o = ctl(&args(&[base, &s(&["--json", "runner", "show", id])]));
    assert!(o.status.success(), "{o:?}");
    serde_json::from_str(&stdout(&o)).unwrap()
}

/// Polls `runner show` until `online` is `want`; how long it took.
pub fn wait_online(base: &[String], id: &str, want: bool, limit: Duration) -> Duration {
    let start = Instant::now();
    loop {
        if show(base, id)["online"].as_bool() == Some(want) {
            return start.elapsed();
        }
        assert!(
            start.elapsed() < limit,
            "{id} not online={want} within {limit:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Every event after `after`, replayed.
pub fn events_after(base: &[String], after: i64) -> Vec<Value> {
    let o = ctl(&args(&[
        base,
        &s(&[
            "events",
            "tail",
            "--after",
            &after.to_string(),
            "--no-follow",
        ]),
    ]));
    assert!(o.status.success(), "{o:?}");
    stdout(&o)
        .lines()
        .map(|l| serde_json::from_str(l).expect(l))
        .collect()
}

pub fn head(base: &[String]) -> i64 {
    events_after(base, 0)
        .last()
        .map_or(0, |e| e["seq"].as_i64().unwrap())
}

#[test]
fn a_real_runner_is_listed_runs_the_noop_and_its_events_show() {
    let (core, url) = loopback_core("runner");
    let ks = core.keystore("mac");
    bootstrap(&core, &ks);
    let a = args(&[&s(&["--keystore", &ks.display().to_string()]), &core.at()]);

    let id = pair_runner(&core, &a, &url, "vm");
    let o = ctl(&args(&[&a, &s(&["runner", "ls"])]));
    assert!(
        o.status.success() && stdout(&o).contains(&format!("{id}\tvm\toffline")),
        "{o:?}"
    );

    let before = head(&a);
    let mut runner = connect(&core, "vm");
    wait_online(&a, &id, true, Duration::from_secs(20));
    let r = show(&a, &id);
    assert_eq!(
        r["drivers"][0]["commands"],
        serde_json::json!(["noop"]),
        "exec stays off: {r}"
    );
    let o = ctl(&args(&[&a, &s(&["runner", "ls"])]));
    let ls = stdout(&o);
    assert!(
        ls.contains(&format!("{id}\tvm\tonline\t0/")) && ls.contains("\tnoop\t"),
        "{ls}"
    );

    let o = ctl(&args(&[&a, &s(&["run", "noop", &id])]));
    assert!(o.status.success(), "{o:?}");
    let out = stdout(&o);
    assert!(
        out.starts_with("ok ") && out.trim_end().ends_with(" ms"),
        "{out}"
    );
    let after = events_after(&a, before);
    let has = |kind: &str| {
        after
            .iter()
            .any(|e| e["kind"] == kind && e["payload"]["device_id"] == *id)
    };
    assert!(has("runner.connected"), "{after:?}");
    assert!(
        after
            .iter()
            .any(|e| e["payload"]["action"] == "runner.command"
                && e["payload"]["details"]["runner"] == *id),
        "the no-op is audited: {after:?}"
    );

    // Killed: offline at once (the socket closes), the disconnect is an event, and the no-op
    // is refused as runner_offline (exit 4).
    let mark = head(&a);
    runner.kill().unwrap();
    runner.wait().unwrap();
    wait_online(&a, &id, false, Duration::from_secs(5));
    assert!(
        events_after(&a, mark)
            .iter()
            .any(|e| e["kind"] == "runner.disconnected")
    );
    let o = ctl(&args(&[&a, &s(&["run", "noop", &id])]));
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("runner_offline"),
        "{o:?}"
    );
    let o = ctl(&args(&[&a, &s(&["run", "noop", "vm"])]));
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert_nothing_secret_printed(&[private_key_of(&ks)]);
}

/// E1 exit gate finding 2: a revoked runner stops (exit 6, said on stderr) instead of redialing
/// forever: at once on the 4001 close, and, started again while revoked, after a few refusals.
#[test]
fn a_revoked_runner_exits_6() {
    let (core, url) = loopback_core("runner-revoked");
    let ks = core.keystore("mac");
    bootstrap(&core, &ks);
    let a = args(&[&s(&["--keystore", &ks.display().to_string()]), &core.at()]);
    let id = pair_runner(&core, &a, &url, "vm");
    let exits_6 = |runner: &mut Child, within: Duration| {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = runner.try_wait().unwrap() {
                break status;
            }
            assert!(start.elapsed() < within, "the runner kept running");
            std::thread::sleep(Duration::from_millis(100));
        };
        let log = std::fs::read_to_string(core.dir.join("vm.log")).unwrap();
        assert_eq!(status.code(), Some(6), "{log}");
        assert!(log.contains("rejected by the Core"), "{log}");
        start.elapsed()
    };

    let mut runner = connect(&core, "vm");
    wait_online(&a, &id, true, Duration::from_secs(20));
    let o = ctl(&args(&[&a, &s(&["device", "revoke", &id])]));
    assert!(o.status.success(), "{o:?}");
    let closed = exits_6(&mut runner, Duration::from_secs(10));

    let mut again = connect(&core, "vm");
    let refused = exits_6(&mut again, Duration::from_secs(20));
    eprintln!(
        "revoked runner: exit 6 {closed:?} after the revoke (4001), and {refused:?} after a \
         restart while revoked (auth_failed x3)"
    );
}
