//! Step-up (spec §8) as ctl does it: the step-up key sealed under a passphrase, `elevate`,
//! the one automatic elevation on `step_up_required`, and the device commands behind it.
//!
//! Not tested here: an elevation running out. The server binary runs on the system clock (no
//! injectable clock outside its unit tests) and its shortest window is 60 s; the server's own
//! tests cover expiry with a fake clock. What is tested is that traffic never extends it.

use std::time::Duration;

use ainkrad_ctl::Error;
use ainkrad_ctl::client::Client;
use ainkrad_ctl::keystore::Keystore;
use ainkrad_ctl::net::{Endpoint, Net};
use ainkrad_ctl::proto::Key;
use ainkrad_ctl::stepup::{self, Passphrase};
use serde_json::Value;

use crate::common::*;
use crate::fake::Fake;

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// `elevated_until` as `health` shows it (from a new session, so as the Core carries it).
fn elevated_until(base: &[String]) -> String {
    let o = ctl(&args(&[base, &s(&["health"])]));
    assert!(o.status.success(), "{o:?}");
    field(&stdout(&o), "elevated_until").unwrap()
}

/// How many `action` audit events the Core has.
fn audited(base: &[String], action: &str) -> usize {
    let o = ctl(&args(&[
        base,
        &s(&["events", "tail", "--after", "0", "--no-follow"]),
    ]));
    assert!(o.status.success(), "{o:?}");
    stdout(&o)
        .lines()
        .filter(|l| {
            let e: Value = serde_json::from_str(l).unwrap();
            e["payload"]["action"] == action
        })
        .count()
}

#[test]
fn elevate_once_and_traffic_never_extends_it() {
    let core = Core::start("elev");
    let ks = core.keystore("mac");
    bootstrap(&core, &ks);
    let a = s(&["--keystore", &ks.display().to_string()]);
    assert_eq!(elevated_until(&a), "-");

    let o = ctl(&args(&[&a, &s(&["elevate"])]));
    assert!(o.status.success(), "{o:?}");
    let until = field(&stdout(&o), "elevated_until").unwrap();
    let left = until.parse::<i64>().unwrap() - ainkrad_ctl::client::unix_now();
    assert!((290..=301).contains(&left), "the default window: {left} s");
    assert_eq!(audited(&a, "auth.step_up"), 1);

    // Traffic, new sessions included, a little later: the Core carries the same instant.
    std::thread::sleep(Duration::from_secs(2));
    for cmd in [&["device", "ls"][..], &["lockouts", "ls"], &["health"]] {
        assert!(ctl(&args(&[&a, &s(cmd)])).status.success(), "{cmd:?}");
    }
    assert_eq!(elevated_until(&a), until, "not extended by traffic");

    // A wrong passphrase: refused here (exit 9), no proof sent, nothing audited or locked.
    let wrong = core.dir.join("wrong-pass");
    std::fs::write(&wrong, "not the passphrase\n").unwrap();
    let w = wrong.display().to_string();
    let o = ctl(&args(&[
        &a,
        &s(&["--stepup-passphrase-file", &w, "elevate"]),
    ]));
    assert_eq!(o.status.code(), Some(9), "{o:?}");
    assert!(stderr(&o).contains("wrong step-up passphrase"), "{o:?}");
    assert_eq!(audited(&a, "auth.step_up"), 1);
    assert!(!stdout(&ctl(&args(&[&a, &s(&["lockouts", "ls"])]))).contains("stepup:"));
    assert_nothing_secret_printed(&[private_key_of(&ks), stepup_key_of(&ks), PASSPHRASE.into()]);
}

fn refused(r: Result<i64, Error>) -> String {
    match r {
        Err(Error::Refused { status, code, .. }) => format!("{status} {code}"),
        other => panic!("{other:?}"),
    }
}

/// A routine-key signature over the right message, and the step-up key over the same fields
/// under another prefix, are both refused; only §8's proof elevates.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_step_up_key_over_the_stepup_message_elevates() {
    let core = Core::start("proof");
    let ks = core.keystore("mac");
    bootstrap(&core, &ks);
    let net = Net::new(Endpoint::Unix(core.sock.clone()), None, None).unwrap();
    let store = Keystore::load(&ks).unwrap();
    let (device, core_fp) = (store.device_id.clone(), store.core_fp.clone());
    let routine = Key::from_pkcs8(store.key.pkcs8()).unwrap();
    let path = stepup::path_for(&ks);
    let key = stepup::load(&path, PASSPHRASE.as_bytes(), &device, &core_fp).unwrap();
    let mut c = Client::new(net, store);
    let right = |s: &str, ch: &str| stepup::message(&core_fp, &device, s, ch);
    let req_prefix = |s: &str, ch: &str| {
        let m = String::from_utf8(right(s, ch)).unwrap();
        m.replacen("AINKRAD-STEPUP-V1", "AINKRAD-REQ-V1", 1)
            .into_bytes()
    };

    let r = c.step_up_with(|m| routine.sign(m), right).await;
    assert_eq!(refused(r), "403 step_up_failed", "the routine key");
    let r = c.step_up_with(|m| key.sign(m), req_prefix).await;
    assert_eq!(refused(r), "403 step_up_failed", "the wrong prefix");
    assert_eq!(c.current().unwrap().elevated_until, None);
    let until = c.step_up_with(|m| key.sign(m), right).await.unwrap();
    assert_eq!(c.current().unwrap().elevated_until, Some(until));
}

const PINNED: &str = "PINNEDPINNEDPINNEDPINNEDPINNEDPINNEDPINNEDA";
const DEVICE: &str = "d_00000000000000000000000000";
const TARGET: &str = "/api/v1/devices/d_11111111111111111111111111";

/// A Core that grants sessions and step-ups and still answers `step_up_required`.
fn insists(method: &str, path: &str) -> (u16, String) {
    let ch = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    match (method, path) {
        ("GET", "/handshake") => (200, format!(r#"{{"identity_fingerprint":"{PINNED}"}}"#)),
        ("POST", "/handshake/challenge" | "/api/v1/auth/step-up/challenge") => {
            (200, format!(r#"{{"challenge":"{ch}","expires_in":60}}"#))
        }
        ("POST", "/handshake/session") => (
            200,
            r#"{"session_id":"s_00000000000000000000000000","expires_at":"2099-01-01T00:00:00.000Z","scopes":["admin"]}"#.into(),
        ),
        ("POST", "/api/v1/auth/step-up") => (
            200,
            r#"{"elevated_until":"2099-01-01T00:05:00.000Z"}"#.into(),
        ),
        ("DELETE", TARGET) => (
            403,
            r#"{"error":"x","code":"step_up_required","message":"x"}"#.into(),
        ),
        _ => (500, "{}".into()),
    }
}

/// A fake Core, and a device paired to it (with a step-up key when `stepup`).
fn fake_device(name: &str, stepup: bool) -> (Fake, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("ctl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fake = Fake::start(dir.join("f.sock"), insists);
    let ks = dir.join("ks").join("keystore.json");
    Keystore {
        device_id: DEVICE.into(),
        core_fp: PINNED.into(),
        endpoint: format!("unix:{}", fake.sock.display()),
        host: None,
        key: Key::generate(),
    }
    .save(&ks)
    .unwrap();
    if stepup {
        let path = stepup::path_for(&ks);
        stepup::save(
            &path,
            &Key::generate(),
            PASSPHRASE.as_bytes(),
            DEVICE,
            PINNED,
        )
        .unwrap();
    }
    (fake, ks)
}

fn hits(fake: &Fake, line: &str) -> usize {
    fake.requests()
        .iter()
        .filter(|r| r.starts_with(line))
        .count()
}

#[test]
fn auto_elevation_happens_once_and_retries_once() {
    let target = TARGET.trim_start_matches("/api/v1/devices/");
    let (fake, ks) = fake_device("auto", true);
    let o = ctl(&s(&[
        "--keystore",
        &ks.display().to_string(),
        "device",
        "revoke",
        target,
    ]));
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    assert!(stderr(&o).contains("step_up_required"), "{o:?}");
    assert_eq!(hits(&fake, &format!("delete {}", TARGET.to_lowercase())), 2);
    assert_eq!(hits(&fake, "post /api/v1/auth/step-up "), 1);

    // No step-up key: a clear refusal (exit 9) and no step-up attempted.
    let (fake, ks) = fake_device("nokey", false);
    let o = ctl(&s(&[
        "--keystore",
        &ks.display().to_string(),
        "device",
        "revoke",
        target,
    ]));
    assert_eq!(o.status.code(), Some(9), "{o:?}");
    assert!(stderr(&o).contains("no step-up key"), "{o:?}");
    assert!(stderr(&o).contains("--no-stepup"), "{o:?}");
    assert_eq!(hits(&fake, &format!("delete {}", TARGET.to_lowercase())), 1);
    assert_eq!(hits(&fake, "post /api/v1/auth/step-up"), 0);
}

/// Pairs `name` with `scopes` (and `extra` pair flags) from `a`; returns its id and keystore.
fn pair_another(
    core: &Core,
    a: &[String],
    name: &str,
    scopes: &str,
    extra: &[String],
) -> (String, std::path::PathBuf) {
    let o = ctl(&args(&[
        a,
        &s(&["device", "add", name, "--scopes", scopes]),
    ]));
    assert!(o.status.success(), "{o:?}");
    let (pairing, code) = (
        field(&stdout(&o), "pairing_id").unwrap(),
        field(&stdout(&o), "code").unwrap(),
    );
    let ks = core.keystore(name);
    let mut claim = spawn_pair(&core.at(), &ks, &code, extra);
    let mut lines = Lines::of(claim.stdout.take().unwrap());
    let wait = Duration::from_secs(20);
    let dev = lines.next(wait).unwrap()["device ".len()..].to_owned();
    let sas = lines.next(wait).unwrap()["sas ".len()..].to_owned();
    let ok = ctl(&args(&[a, &s(&["device", "approve", &pairing, &sas])]));
    assert!(ok.status.success(), "{ok:?}");
    assert_eq!(lines.next(wait).as_deref(), Some("status active"));
    assert!(claim.wait().unwrap().success());
    record(lines.seen.clone());
    (dev, ks)
}

#[test]
fn device_management_and_the_last_admin() {
    let core = Core::start("manage");
    let ks_a = core.keystore("mac");
    let (dev_a, _) = bootstrap(&core, &ks_a);
    let a = s(&["--keystore", &ks_a.display().to_string()]);

    // The only admin can be neither demoted nor revoked (409, in words).
    for cmd in [&["scopes", &dev_a, "read"][..], &["revoke", &dev_a]] {
        let o = ctl(&args(&[&a, &s(&["device"]), &s(cmd)]));
        assert_eq!(o.status.code(), Some(4), "{o:?}");
        assert!(stderr(&o).contains("409 conflict"), "{o:?}");
        assert!(stderr(&o).contains("no active admin device"), "{o:?}");
    }

    // A device enrolled without a step-up key, even an admin, cannot elevate.
    let (dev_b, ks_b) = pair_another(&core, &a, "box", "read,admin", &s(&["--no-stepup"]));
    assert!(!stepup::path_for(&ks_b).exists());
    let b = s(&["--keystore", &ks_b.display().to_string()]);
    let shown = stdout(&ctl(&args(&[&a, &s(&["device", "show", &dev_b])])));
    assert!(
        shown.starts_with(&format!("{dev_b}\tdevice\tbox\tactive\tadmin,read\t")),
        "{shown}"
    );
    assert!(shown.trim_end().ends_with("\tno-stepup"), "{shown}");
    for cmd in [&["elevate"][..], &["device", "rename", &dev_a, "x"]] {
        let o = ctl(&args(&[&b, &s(cmd)]));
        assert_eq!(o.status.code(), Some(9), "{o:?}");
        assert!(
            stderr(&o).contains("this device has no step-up key"),
            "{o:?}"
        );
    }

    // Rename and scope change, from the device that can elevate.
    let o = ctl(&args(&[
        &a,
        &s(&["device", "rename", &dev_b, "old", "box"]),
    ]));
    assert!(o.status.success(), "{o:?}");
    assert!(stdout(&o).contains("\told box\t"), "{o:?}");
    let o = ctl(&args(&[&a, &s(&["device", "scopes", &dev_b, "read"])]));
    assert!(o.status.success(), "{o:?}");
    assert!(stdout(&o).contains("\tactive\tread\t"), "{o:?}");
    let shown = stdout(&ctl(&args(&[&a, &s(&["device", "show", &dev_a])])));
    assert!(shown.trim_end().ends_with("\tstepup"), "{shown}");

    // Lockouts: listed; clearing goes through the elevation to the route (404: nothing there).
    assert!(ctl(&args(&[&a, &s(&["lockouts", "ls"])])).status.success());
    let o = ctl(&args(&[&a, &s(&["lockouts", "clear", "ip:203.0.113.9"])]));
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    assert!(stderr(&o).contains("404 not_found"), "{o:?}");
    assert_eq!(audited(&a, "device.renamed"), 1);
    assert_eq!(audited(&a, "device.scopes_changed"), 1);
    assert_nothing_secret_printed(&[private_key_of(&ks_a), private_key_of(&ks_b)]);
}

/// `Passphrase` reads a file, dropping one trailing newline only.
#[test]
fn the_passphrase_file_is_read_as_written() {
    let p = Passphrase::new(Some(passphrase_file().to_str().unwrap()));
    assert_eq!(&*p.read(true).unwrap(), PASSPHRASE.as_bytes());
}
