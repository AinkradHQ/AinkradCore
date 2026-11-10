//! `status`: versions from the manifest, files checked and hashed but never run.
mod common;

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;

use common::*;
use serde_json::Value;

fn state_of(v: &Value, name: &str) -> String {
    let b = v["result"]["binaries"].as_array().unwrap();
    b.iter().find(|b| b["name"] == name).unwrap()["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn chmod(p: &std::path::Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The marker a binary would create if it were ever run.
const A: &str = "#!/bin/sh\n: > /nonexistent-dir/MARKER_A\n";
const B: &str = "#!/bin/sh\n: > /nonexistent-dir/MARKER_B\n";

fn set_up(fx: &Fx) -> (String, String) {
    let (sa, sb) = (
        put_bin(fx, "ainkrad-core-server", A),
        put_bin(fx, "ainkrad-runner", B),
    );
    manifest(
        fx,
        &[
            ("ainkrad-core-server", "0.1.1", &sa, A.len()),
            ("ainkrad-runner", "0.1.1", &sb, B.len()),
        ],
    );
    (sa, sb)
}

#[test]
fn versions_come_from_the_manifest_and_nothing_installed_is_run() {
    let fx = Fx::new();
    let (sa, _) = set_up(&fx);
    // Each "binary" would fail loudly if executed; `status` only reads it.
    let v = fx.call("status", "{}");
    let r = &v["result"];
    assert_eq!(
        (r["manifest"].as_str(), r["bin_dir_safe"].as_bool()),
        (Some("ok"), Some(true))
    );
    let bins = r["binaries"].as_array().unwrap();
    assert_eq!(bins.len(), 2);
    assert_eq!(
        (bins[0]["version"].as_str(), bins[0]["state"].as_str()),
        (Some("0.1.1"), Some("ok"))
    );
    assert_eq!(bins[0]["sha256_12"], &sa[..12]);
    assert_eq!(r["units"]["core"]["active"], "active");
    assert_eq!(r["units"]["core"]["restarts"], 2);
    assert!(
        r["units"].get("runner").is_none() && r["units"].get("backup_timer").is_none(),
        "absent units are left out"
    );
    // The only processes are `systemctl show` for the three fixed units.
    let calls = fx.fake.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    for (prog, args) in calls.iter() {
        assert_eq!(prog, "/usr/bin/systemctl");
        assert_eq!(
            &args[..3],
            [
                "show",
                "-p",
                "ActiveState,SubState,ActiveEnterTimestamp,NRestarts,LoadState"
            ]
        );
    }
    let units: Vec<&str> = calls.iter().map(|(_, a)| a[3].as_str()).collect();
    assert_eq!(
        units,
        [
            "ainkrad-core.service",
            "ainkrad-runner.service",
            "ainkrad-backup.timer"
        ]
    );
    assert!(fx.log().is_empty());
}

#[test]
fn a_changed_missing_or_unlisted_file_is_flagged() {
    let fx = Fx::new();
    let (sa, _) = set_up(&fx);
    // Same size, other content.
    let other = A.replace("MARKER_A", "MARKER_X");
    std::fs::write(fx.bin().join("ainkrad-core-server"), &other).unwrap();
    chmod(&fx.bin().join("ainkrad-core-server"), 0o755);
    // A different size is `differs` without hashing at all.
    manifest(
        &fx,
        &[
            ("ainkrad-core-server", "0.1.1", &sa, A.len()),
            ("ainkrad-runner", "0.1.1", &sa, 999),
            ("ainkrad-host", "0.1.1", &sa, 10),
        ],
    );
    let v = fx.call("status", "{}");
    assert_eq!(state_of(&v, "ainkrad-core-server"), "differs");
    assert_eq!(state_of(&v, "ainkrad-runner"), "differs");
    assert_eq!(state_of(&v, "ainkrad-host"), "missing");
    assert_eq!(
        fx.ctx.hashes.load(Ordering::Relaxed),
        1,
        "the size mismatch cost no hash"
    );
}

#[test]
fn a_symlink_a_hard_link_and_a_writable_file_are_unsafe_and_never_hashed() {
    let fx = Fx::new();
    let (sa, sb) = set_up(&fx);
    // A symlink to a perfectly good file.
    std::fs::write(fx.dir.path().join("elsewhere"), A).unwrap();
    std::fs::remove_file(fx.bin().join("ainkrad-core-server")).unwrap();
    std::os::unix::fs::symlink(
        fx.dir.path().join("elsewhere"),
        fx.bin().join("ainkrad-core-server"),
    )
    .unwrap();
    // A hard link: nlink 2.
    std::fs::hard_link(
        fx.bin().join("ainkrad-runner"),
        fx.dir.path().join("second-name"),
    )
    .unwrap();
    // And a file anyone in the group may write.
    let w = put_bin(&fx, "ainkrad-ctl", A);
    chmod(&fx.bin().join("ainkrad-ctl"), 0o775);
    manifest(
        &fx,
        &[
            ("ainkrad-core-server", "1", &sa, A.len()),
            ("ainkrad-runner", "1", &sb, B.len()),
            ("ainkrad-ctl", "1", &w, A.len()),
        ],
    );
    let v = fx.call("status", "{}");
    for n in ["ainkrad-core-server", "ainkrad-runner", "ainkrad-ctl"] {
        assert_eq!(state_of(&v, n), "unsafe", "{n}");
    }
    assert_eq!(
        fx.ctx.hashes.load(Ordering::Relaxed),
        0,
        "an unsafe file is not even hashed"
    );
}

#[test]
fn a_writable_bin_dir_is_reported_and_marks_everything_unsafe() {
    let fx = Fx::new();
    set_up(&fx);
    chmod(&fx.bin(), 0o775);
    let v = fx.call("status", "{}");
    assert_eq!(v["result"]["bin_dir_safe"], false);
    assert_eq!(state_of(&v, "ainkrad-runner"), "unsafe");
    chmod(&fx.bin(), 0o755);
    assert_eq!(fx.call("status", "{}")["result"]["bin_dir_safe"], true);
}

#[test]
fn hashes_are_cached_until_the_file_changes() {
    let fx = Fx::new();
    set_up(&fx);
    fx.call("status", "{}");
    assert_eq!(fx.ctx.hashes.load(Ordering::Relaxed), 2);
    for _ in 0..3 {
        assert_eq!(state_of(&fx.call("status", "{}"), "ainkrad-runner"), "ok");
    }
    assert_eq!(
        fx.ctx.hashes.load(Ordering::Relaxed),
        2,
        "a hash is computed only after a change"
    );
    // A same-size rewrite changes mtime and ctime: hashed again, and now differs.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let new = B.replace("MARKER_B", "MARKER_Z");
    std::fs::write(fx.bin().join("ainkrad-runner"), &new).unwrap();
    assert_eq!(
        state_of(&fx.call("status", "{}"), "ainkrad-runner"),
        "differs"
    );
    assert_eq!(fx.ctx.hashes.load(Ordering::Relaxed), 3);
}

#[test]
fn a_bad_or_missing_manifest_lists_no_binaries_and_status_still_answers() {
    let fx = Fx::new();
    let v = fx.call("status", "{}");
    assert_eq!(
        (
            v["result"]["manifest"].as_str(),
            v["result"]["binaries"].as_array().map(Vec::len)
        ),
        (Some("absent"), Some(0))
    );
    let sha = "a".repeat(64);
    for bad in [
        "not json".to_string(),
        r#"{"v":2,"binaries":[]}"#.to_string(),
        format!(
            r#"{{"v":1,"binaries":[{{"name":"../etc/passwd","version":"1","sha256":"{sha}","size":1}}]}}"#
        ),
        format!(
            r#"{{"v":1,"binaries":[{{"name":"a/b","version":"1","sha256":"{sha}","size":1}}]}}"#
        ),
        format!(
            r#"{{"v":1,"binaries":[{{"name":"a","version":"1","sha256":"{sha}","size":1,"x":1}}]}}"#
        ),
        format!(
            r#"{{"v":1,"binaries":[{{"name":"a","version":"1\n2","sha256":"{sha}","size":1}}]}}"#
        ),
        r#"{"v":1,"binaries":[{"name":"a","version":"1","sha256":"XYZ","size":1}]}"#.to_string(),
    ] {
        std::fs::write(fx.state().join("installed.json"), bad).unwrap();
        let v = fx.call("status", "{}");
        assert_eq!(v["result"]["manifest"], "invalid");
        assert_eq!(v["result"]["binaries"].as_array().unwrap().len(), 0);
    }
}

#[test]
fn a_binary_owned_by_someone_else_is_unsafe() {
    if ainkrad_sys::getuid() != 0 {
        eprintln!("skipped: needs root to chown");
        return;
    }
    let mut fx = Fx::new();
    set_up(&fx);
    fx.ctx.owner_uid = 0;
    std::os::unix::fs::chown(fx.bin().join("ainkrad-runner"), Some(65534), None).unwrap();
    let v = fx.call("status", "{}");
    assert_eq!(state_of(&v, "ainkrad-runner"), "unsafe");
    assert_eq!(state_of(&v, "ainkrad-core-server"), "ok");
    std::os::unix::fs::chown(fx.bin(), Some(65534), None).unwrap();
    assert_eq!(
        fx.call("status", "{}")["result"]["bin_dir_safe"],
        false,
        "a bin dir owned by another user"
    );
}

#[test]
fn the_host_id_is_reported_only_when_it_is_a_plain_token() {
    let fx = Fx::new();
    assert_eq!(fx.call("status", "{}")["result"]["host_id"], Value::Null);
    std::fs::write(fx.state().join("host_id"), "h_AbC-123\n").unwrap();
    assert_eq!(fx.call("status", "{}")["result"]["host_id"], "h_AbC-123");
    std::fs::write(fx.state().join("host_id"), "has space\n").unwrap();
    assert_eq!(fx.call("status", "{}")["result"]["host_id"], Value::Null);
}
