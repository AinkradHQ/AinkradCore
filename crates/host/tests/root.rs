//! Live checks against the real `systemctl` and `journalctl`. They need root and a running systemd,
//! so they skip themselves anywhere else (`cargo test` stays green for everyone); on a throwaway
//! host run them as root: `sudo -E cargo test -p ainkrad-host --test root`.
mod common;

use common::*;
use serde_json::Value;

fn live() -> Option<Fx> {
    if ainkrad_sys::getuid() != 0 || !std::path::Path::new("/run/systemd/system").exists() {
        eprintln!("skipped: needs root and systemd");
        return None;
    }
    let mut fx = Fx::new();
    fx.ctx.exec = Box::new(ainkrad_host::Real);
    fx.ctx.owner_uid = 0;
    fx.ctx.ainkrad_uid = Some(0); // the peer is this test, uid 0
    Some(fx)
}

#[test]
fn status_and_logs_work_against_the_real_systemd() {
    let Some(fx) = live() else { return };
    let v = fx.call("status", "{}");
    assert_eq!(v["ok"], true, "{v}");
    let core = &v["result"]["units"]["core"];
    assert!(
        core["load"].is_string() && core["active"].is_string(),
        "{core}"
    );
    // The real journalctl, the real argv, and an `-r --cursor` page through whatever the box holds.
    let first = fx.call("logs", r#"{"unit":"core","lines":3}"#);
    assert_eq!(first["ok"], true, "{first}");
    // A cursor journalctl does not know is a plain `failed`, not a hang or a panic.
    let bad = fx.call(
        "logs",
        r#"{"unit":"core","before":"s=00;i=1;b=00;m=0;t=0;x=0"}"#,
    );
    assert!(bad["ok"] == true || bad["code"] == "failed", "{bad}");
    assert!(!fx.log().contains(" ok "));
}

#[test]
fn the_real_journal_pages_without_a_repeat_or_a_skip() {
    let Some(_fx) = live() else { return };
    // `ssh.service` stands in only at the journalctl level: the helper's units are fixed, so this
    // drives journalctl directly with the exact argv shape the helper uses.
    let run = |extra: &[&str]| -> Vec<Value> {
        let mut args = vec!["-u", "ssh.service", "-o", "json", "--no-pager"];
        args.extend_from_slice(extra);
        let out = std::process::Command::new("/usr/bin/journalctl")
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };
    let newest = run(&["-n", "7"]);
    if newest.len() < 7 {
        eprintln!("skipped: too few ssh.service entries");
        return;
    }
    let oldest_seen = newest[0]["__CURSOR"].as_str().unwrap().to_owned();
    let cursor = format!("--cursor={oldest_seen}");
    let older = run(&["-n", "4", "-r", &cursor]);
    assert_eq!(
        older[0]["__CURSOR"],
        oldest_seen.as_str(),
        "-r --cursor starts at the cursor's own entry"
    );
    assert_ne!(older[1]["__CURSOR"], oldest_seen.as_str());
}
