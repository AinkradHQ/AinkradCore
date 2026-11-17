//! V6-01 acceptance, runner half (Linux, real bubblewrap; these fail, never skip, where it cannot run).
//! A fake helper (a bash script) plays the hostile cases a parser bug could cause: a crash, a
//! runaway allocation, a hang, an attempt at the network or the host. With `AINKRAD_DESIGN_HELPER`
//! set to a built `ainkrad-design`, the real helper gets the hostile font/SVG/PNG/zip set too.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{
    Command, DesignCheck, DesignDoc, DesignFile, DesignRender, DesignShot, DesignShotFile,
    ErrorCode, Reply,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::oneshot;

use super::{DesignConfig, DesignDriver, path_ok};

/// A helper script in its own directory (bound read-only into the sandbox like the real one).
fn helper(name: &str, body: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "design-fake-{name}-{}-{:?}",
        std::process::id(),
        Instant::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("ainkrad-design");
    std::fs::write(&p, format!("#!/bin/bash\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    (dir, p)
}

fn driver(p: PathBuf) -> DesignDriver {
    let mut c = DesignConfig::new(p, None);
    c.timeout = Duration::from_secs(5);
    c.max_rss = 256 << 20;
    DesignDriver::new(c)
}

fn check(data: &[u8]) -> Command {
    Command::DesignCheck(DesignCheck {
        kind: "font".into(),
        data: STANDARD.encode(data),
    })
}

async fn run(d: &DesignDriver, c: &Command) -> Result<Reply, ainkrad_proto::v2::StreamError> {
    let (_keep, rx) = oneshot::channel();
    d.run(c, rx).await
}

fn checked(r: Reply) -> (bool, Option<String>) {
    match r {
        Reply::DesignCheck(c) => (c.ok, c.reason),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_crashing_helper_is_reported_and_the_runner_carries_on() {
    let (dir, p) = helper("crash", "kill -SEGV $$");
    let d = driver(p);
    let e = run(&d, &check(b"x")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignFailed, "{e:?}");
    assert!(
        e.message.contains("signal") || e.message.contains("status"),
        "{e:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_helper_that_eats_memory_is_stopped() {
    // Grows a string without bound: ulimit -v or the RSS watch ends it, not the (long) timeout.
    let (dir, p) = helper("mem", "x=a; while true; do x=$x$x; done");
    let mut c = DesignConfig::new(p, None);
    c.timeout = Duration::from_secs(60);
    c.max_rss = 256 << 20;
    let e = run(&DesignDriver::new(c), &check(b"x")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignFailed, "{e:?}");
    assert!(!e.message.contains("time limit"), "{e:?}");
    println!("memory: {}", e.message);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Under the address-space cap, so only the outside RSS watch can stop it (what Chromium gets).
#[tokio::test]
async fn the_rss_watch_stops_a_tree_over_its_memory() {
    let (dir, p) = helper(
        "rss",
        r#"m=$(head -c 1048576 /dev/zero | tr '\0' a); x=""; while true; do x="$x$m"; done"#,
    );
    let mut c = DesignConfig::new(p, None);
    c.timeout = Duration::from_secs(60);
    c.max_rss = 64 << 20;
    c.max_vm = 1 << 30;
    let e = run(&DesignDriver::new(c), &check(b"x")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignFailed, "{e:?}");
    assert!(e.message.contains("more memory than allowed"), "{e:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_hanging_helper_is_stopped_at_its_time_limit() {
    let (dir, p) = helper("hang", "while true; do :; done");
    let mut c = DesignConfig::new(p, None);
    c.timeout = Duration::from_secs(1);
    let e = run(&DesignDriver::new(c), &check(b"x")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignFailed);
    assert!(
        e.message.contains("time") || e.message.contains("signal"),
        "{e:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// No network, no host files, a read-only input: the fake helper reports what it could reach.
#[tokio::test]
async fn the_sandbox_has_no_network_and_sees_only_its_job() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let body = format!(
        r#"r=""
(exec 3<>/dev/tcp/1.1.1.1/53) 2>/dev/null && r="$r net-ip"
(exec 3<>/dev/tcp/127.0.0.1/22) 2>/dev/null && r="$r net-lo"
getent hosts example.com >/dev/null 2>&1 && r="$r dns"
[ -e "{home}" ] && r="$r home"
[ -e /etc/passwd ] && r="$r etc"
[ -e /var/lib ] && r="$r var"
touch /in/x 2>/dev/null && r="$r in-writable"
touch /usr/x 2>/dev/null && r="$r usr-writable"
[ -r /in/job.json ] || r="$r no-job"
[ -z "$(env | grep -v -E '^(HOME|PATH|LANG|PWD|SHLVL|_|OLDPWD)=')" ] || r="$r env"
if [ -z "$r" ]; then echo '{{"ok":true}}'; else echo "{{\"ok\":false,\"reason\":\"$r\"}}"; fi"#
    );
    let (dir, p) = helper("reach", &body);
    let (ok, why) = checked(run(&driver(p), &check(b"x")).await.unwrap());
    assert!(ok, "reached: {why:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn output_that_is_not_the_ops_reply_is_refused() {
    let (dir, p) = helper("junk", r#"echo '{"png":"x","width":1,"height":1}'"#);
    let e = run(&driver(p), &check(b"x")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DesignFailed);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn two_in_flight_at_most() {
    let (dir, p) = helper("slots", "exit 0");
    let d = driver(p);
    let a = d.slot().unwrap();
    let _b = d.slot().unwrap();
    assert_eq!(d.slot().unwrap_err().code, ErrorCode::Busy);
    drop(a);
    assert!(d.slot().is_ok());
    assert_eq!(d.info().streams, Some(2));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn an_oversized_job_is_refused_before_anything_runs() {
    let (dir, p) = helper("big", "touch /out/ran; echo '{\"ok\":true}'");
    let e = run(&driver(p), &check(&vec![0u8; 6 << 20]))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::TooLarge);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn shot_paths_are_relative_and_plain() {
    for ok in ["index.html", "a/b.css", "img/x y.png"] {
        assert!(path_ok(ok), "{ok}");
    }
    for bad in [
        "",
        "/etc/passwd",
        "../x",
        "a/../b",
        "a//b",
        "./a",
        "a\\b",
        "a\0b",
    ] {
        assert!(!path_ok(bad), "{bad:?}");
    }
}

// ---- the real helper and Chromium (set AINKRAD_DESIGN_HELPER / AINKRAD_CHROMIUM) ----

fn real() -> Option<DesignDriver> {
    let helper = PathBuf::from(std::env::var_os("AINKRAD_DESIGN_HELPER")?);
    let chromium = std::env::var_os("AINKRAD_CHROMIUM").map(PathBuf::from);
    Some(DesignDriver::new(DesignConfig::new(helper, chromium)))
}

/// A TrueType header that claims 65 535 tables and has none.
fn font_tables_lie() -> Vec<u8> {
    let mut v = vec![0, 1, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
    v.extend(std::iter::repeat_n(0x41, 64));
    v
}

/// A PNG header for a 100 000 x 100 000 image, and nothing behind it.
fn png_huge() -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    v.extend(100_000u32.to_be_bytes());
    v.extend(100_000u32.to_be_bytes());
    v.extend([8, 6, 0, 0, 0, 0, 0, 0, 0]);
    v
}

fn laughs() -> Vec<u8> {
    let mut s = String::from("<?xml version=\"1.0\"?><!DOCTYPE l [<!ENTITY a \"aaaaaaaaaa\">");
    for i in 1..10 {
        let p = (b'a' + i as u8 - 1) as char;
        let c = (b'a' + i as u8) as char;
        s += &format!("<!ENTITY {c} \"{}\">", format!("&{p};").repeat(10));
    }
    s += "]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&j;</text></svg>";
    s.into_bytes()
}

fn doc_with_image(hash: &str, bytes: &[u8]) -> Command {
    let doc = serde_json::json!({
        "meta": {},
        "nodes": {
            "n_aaaaaaaaaaaa": {"type": "page", "parent": null, "order": "a", "clock": 1, "name": "P", "props": {}},
            "n_bbbbbbbbbbbb": {"type": "frame", "parent": "n_aaaaaaaaaaaa", "order": "a", "clock": 1, "name": "S",
                "props": {"x": 0, "y": 0, "w": 200, "h": 100}},
            "n_cccccccccccc": {"type": "image", "parent": "n_bbbbbbbbbbbb", "order": "a", "clock": 1, "name": "I",
                "props": {"w": 100, "h": 50, "asset": hash}}
        }
    });
    Command::DesignRender(DesignRender {
        doc: DesignDoc {
            doc_id: "dd_hostile".into(),
            doc,
            system_id: None,
            system: None,
            theme: "day".into(),
            page: 0,
            fonts: vec![],
            images: vec![DesignFile {
                sha256: hash.into(),
                data: STANDARD.encode(bytes),
            }],
            fallback_font: None,
        },
        node: None,
        scale: 1.0,
    })
}

#[tokio::test]
async fn the_real_helper_survives_the_hostile_set() {
    let Some(d) = real() else {
        eprintln!("SKIPPED: set AINKRAD_DESIGN_HELPER to a built ainkrad-design");
        return;
    };
    let mut rng = 0x2545_f491_4f6c_dd1du64;
    let noise: Vec<u8> = (0..65_536)
        .map(|_| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng as u8
        })
        .collect();
    let fonts: [(&str, Vec<u8>); 4] = [
        ("noise", noise.clone()),
        ("tables-lie", font_tables_lie()),
        ("otto-empty", b"OTTO\0\0\0\0".to_vec()),
        ("woff2-truncated", b"wOF2\0\x01\0\0\0\0\0\0".to_vec()),
    ];
    for (name, bytes) in fonts {
        let r = run(&d, &check(&bytes)).await;
        println!("font {name}: {r:?}");
        match r {
            Ok(r) => assert!(!checked(r).0, "{name} passed the check"),
            Err(e) => assert_eq!(e.code, ErrorCode::DesignFailed, "{name}: {e:?}"),
        }
    }
    let h = "e".repeat(64);
    for (name, bytes) in [
        ("png-huge", png_huge()),
        ("svg-laughs", laughs()),
        ("noise", noise),
    ] {
        let r = run(&d, &doc_with_image(&h, &bytes)).await;
        println!("image {name}: {:?}", r.as_ref().map(|_| "rendered"));
        match r {
            Ok(Reply::DesignRender(i)) => assert!(i.width >= 1),
            Ok(other) => panic!("{other:?}"),
            Err(e) => assert_eq!(e.code, ErrorCode::DesignFailed, "{name}: {e:?}"),
        }
    }
    // After all of it, the driver still answers a good job.
    let ok = run(&d, &doc_with_image(&h, b"")).await;
    assert!(matches!(ok, Ok(Reply::DesignRender(_))), "{ok:?}");
}

#[tokio::test]
async fn chromium_shots_a_page_with_no_network() {
    let Some(d) = real().filter(|d| d.config.chromium.is_some()) else {
        eprintln!("SKIPPED: set AINKRAD_DESIGN_HELPER and AINKRAD_CHROMIUM");
        return;
    };
    // Its script runs and tries the network (the sandbox has none); the shot still comes back.
    let html = r#"<!doctype html><html><body style="margin:0;background:#00f">
<script>
document.body.style.background = '#0f0';
fetch('http://1.1.1.1/').then(() => document.body.style.background = '#f00').catch(() => {});
</script></body></html>"#;
    let shot = Command::DesignShot(DesignShot {
        files: vec![DesignShotFile {
            path: "page one/index.html".into(),
            data: STANDARD.encode(html),
        }],
        entry: "page one/index.html".into(),
        width: 64,
        height: 48,
        scale: 2.0,
    });
    let r = run(&d, &shot).await.unwrap();
    let Reply::DesignShot(i) = r else { panic!() };
    assert_eq!((i.width, i.height), (128, 96));
    assert!(STANDARD.decode(i.png).unwrap().starts_with(b"\x89PNG"));
}
