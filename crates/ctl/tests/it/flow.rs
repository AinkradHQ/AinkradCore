//! The happy path against the real server, as the exit gate runs it: bootstrap the first
//! device, pair a second one through the real flow (ctl drives both sides), scopes honoured,
//! the audit trail in the event stream, revocation closing the stream, and a tail that
//! survives `kill -9` of the Core with no gap and no repeat.

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::common::*;

fn events(text: &str) -> Vec<Value> {
    text.lines()
        .map(|l| serde_json::from_str(l).expect(l))
        .collect()
}

fn action(e: &Value) -> &str {
    e["payload"]["action"].as_str().unwrap_or_default()
}

fn latest(base: &[String]) -> i64 {
    let o = ctl(&args(&[
        base,
        &s(&["events", "tail", "--after", "0", "--no-follow"]),
    ]));
    assert!(o.status.success(), "{o:?}");
    events(&stdout(&o))
        .last()
        .map_or(0, |e| e["seq"].as_i64().unwrap())
}

/// `device add`: the pairing id and the code.
fn add(base: &[String], name: &str, scopes: &str) -> (String, String) {
    let o = ctl(&args(&[
        base,
        &s(&["device", "add", name, "--scopes", scopes]),
    ]));
    assert!(o.status.success(), "{o:?}");
    let out = stdout(&o);
    (
        field(&out, "pairing_id").unwrap(),
        field(&out, "code").unwrap(),
    )
}

#[test]
fn bootstrap_pair_approve_events_and_revoke() {
    let core = Core::start("flow");
    let (ks_a, ks_b) = (core.keystore("mac"), core.keystore("phone"));
    let (dev_a, core_fp) = bootstrap(&core, &ks_a);
    let a = s(&["--keystore", &ks_a.display().to_string()]);
    let b = s(&["--keystore", &ks_b.display().to_string()]);

    let h = ctl(&args(&[&a, &s(&["health"])]));
    assert!(h.status.success(), "{h:?}");
    let out = stdout(&h);
    assert_eq!(
        field(&out, "core_fp").unwrap(),
        format!("{core_fp} (matches the pinned one)")
    );
    assert!(
        out.contains(&dev_a) && field(&out, "scopes").unwrap().contains("admin"),
        "{out}"
    );

    // The approver starts a pairing; the new device claims it with the typed code (its Core
    // fingerprint from /handshake, confirmed by the SAS).
    let (pairing, code) = add(&a, "phone", "read");
    let mut claim = spawn_pair(&core.at(), &ks_b, &code.to_lowercase(), &[]);
    let mut claimant = Lines::of(claim.stdout.take().unwrap());
    let wait = Duration::from_secs(20);
    let dev_b = claimant
        .next(wait)
        .unwrap()
        .strip_prefix("device ")
        .unwrap()
        .to_owned();
    let sas = claimant
        .next(wait)
        .unwrap()
        .strip_prefix("sas ")
        .unwrap()
        .to_owned();
    let view = stdout(&ctl(&args(&[&a, &s(&["device", "pairing", &pairing])])));
    assert_eq!(field(&view, "status").as_deref(), Some("claimed"));
    assert_eq!(
        field(&view, "sas").as_deref(),
        Some(sas.as_str()),
        "the Core computed the same SAS"
    );
    assert_eq!(field(&view, "device_id").as_deref(), Some(dev_b.as_str()));

    // A wrong SAS is refused and the device stays pending (spec §17 case 19).
    let wrong = ctl(&args(&[
        &a,
        &s(&["device", "approve", &pairing, "AAAA-BBBB-CCCC-DDDD"]),
    ]));
    assert_eq!(wrong.status.code(), Some(4), "{wrong:?}");
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("sas_mismatch"));

    // The operator types the SAS the new device shows.
    let ok = ctl(&args(&[
        &a,
        &s(&["device", "approve", &pairing, &sas.to_lowercase()]),
    ]));
    assert!(ok.status.success(), "{ok:?}");
    assert_eq!(stdout(&ok).trim(), format!("approved {dev_b}"));
    assert_eq!(claimant.next(wait).as_deref(), Some("status active"));
    let done = claim.wait_with_output().unwrap();
    assert!(done.status.success(), "{done:?}");
    record(format!(
        "{}{}",
        claimant.seen,
        String::from_utf8_lossy(&done.stderr)
    ));

    // Scopes are honoured: the phone reads, it does not administer.
    let hb = ctl(&args(&[&b, &s(&["health", "--json"])]));
    assert!(hb.status.success(), "{hb:?}");
    let hb: Value = serde_json::from_str(&stdout(&hb)).unwrap();
    assert_eq!(
        (hb["device_id"].as_str(), hb["scopes"].clone()),
        (Some(dev_b.as_str()), serde_json::json!(["read"]))
    );
    let denied = ctl(&args(&[&b, &s(&["device", "ls"])]));
    assert_eq!(denied.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("forbidden_scope"));
    let shown = stdout(&ctl(&args(&[&a, &s(&["device", "show", &dev_b])])));
    assert!(
        shown.starts_with(&format!("{dev_b}\tdevice\tphone\tactive\tread\t")),
        "{shown}"
    );
    assert_eq!(
        stdout(&ctl(&args(&[&a, &s(&["device", "ls"])])))
            .lines()
            .count(),
        2
    );

    // The audit trail of the pairing, replayed over HTTP, in order.
    let all = events(&stdout(&ctl(&args(&[
        &a,
        &s(&["events", "tail", "--after", "0", "--no-follow"]),
    ]))));
    let seqs: Vec<i64> = all.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    for wanted in [
        "pairing.created",
        "pairing.claimed",
        "pairing.refused",
        "pairing.approved",
    ] {
        assert!(
            all.iter()
                .any(|e| e["kind"] == "audit" && action(e) == wanted),
            "no {wanted} in {all:?}"
        );
    }
    assert!(
        all.iter()
            .any(|e| action(e) == "pairing.approved" && e["payload"]["details"]["device"] == *dev_b),
        "the approval names the new device"
    );

    // The audit stream is the admin's (#21): the read-only phone's view of it is empty.
    let none = ctl(&args(&[
        &b,
        &s(&["events", "tail", "--after", "0", "--no-follow"]),
    ]));
    assert!(
        none.status.success() && stdout(&none).is_empty(),
        "{none:?}"
    );
    // Widened to admin (a scope change: elevated, audited), it sees the stream.
    let o = ctl(&args(&[
        &a,
        &s(&["device", "scopes", &dev_b, "read,admin"]),
    ]));
    assert!(o.status.success(), "{o:?}");
    assert!(stdout(&o).contains("\tactive\tread,admin\t"), "{o:?}");

    // The phone follows the live stream; revoking it closes the stream with 4001 (exit 6).
    let from = latest(&a);
    let mut tail = spawn_ctl(&args(&[
        &b,
        &s(&["events", "tail", "--after", &(from - 1).to_string()]),
    ]));
    let mut lines = Lines::of(tail.stdout.take().unwrap());
    assert!(lines.next(wait).is_some(), "the replayed event");
    std::thread::sleep(Duration::from_millis(500));
    add(&a, "watch", "read");
    let live: Value = serde_json::from_str(&lines.next(wait).expect("a live event")).unwrap();
    assert_eq!(action(&live), "pairing.created");
    let revoked = ctl(&args(&[&a, &s(&["device", "revoke", &dev_b])]));
    assert!(revoked.status.success(), "{revoked:?}");
    let at = Instant::now();
    let status = loop {
        if let Some(st) = tail.try_wait().unwrap() {
            break st;
        }
        assert!(
            at.elapsed() < Duration::from_secs(5),
            "the stream outlived the revocation"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(6), "exit 6: revoked");
    let after = ctl(&args(&[&b, &s(&["health"])]));
    assert_eq!(
        after.status.code(),
        Some(4),
        "a revoked device is refused: {after:?}"
    );
    assert!(String::from_utf8_lossy(&after.stderr).contains("auth_failed"));

    let mut secrets = vec![
        private_key_of(&ks_a),
        private_key_of(&ks_b),
        code.clone(),
        code.replace('-', ""),
    ];
    secrets.push(code.to_lowercase());
    secrets.push(PASSPHRASE.to_owned());
    secrets.push(stepup_key_of(&ks_a));
    assert_nothing_secret_printed(&secrets);
}

/// Exit-gate step 5: `kill -9` the Core while a tail follows it; after the restart the tail
/// has every event exactly once, in order: what a fresh replay shows.
#[test]
fn tail_resumes_across_kill9_without_gap_or_repeat() {
    let mut core = Core::start("kill");
    let ks = core.keystore("mac");
    bootstrap(&core, &ks);
    let a = s(&["--keystore", &ks.display().to_string()]);
    let from = latest(&a);
    let mut tail = spawn_ctl(&args(&[
        &a,
        &s(&["events", "tail", "--after", &from.to_string()]),
    ]));
    let mut lines = Lines::of(tail.stdout.take().unwrap());
    std::thread::sleep(Duration::from_millis(500));
    add(&a, "one", "read");
    let wait = Duration::from_secs(20);
    assert!(lines.next(wait).is_some(), "live before the kill");
    core.restart();
    add(&a, "two", "read");
    add(&a, "three", "read");
    let replay = events(&stdout(&ctl(&args(&[
        &a,
        &s(&[
            "events",
            "tail",
            "--after",
            &from.to_string(),
            "--no-follow",
        ]),
    ]))));
    assert!(replay.len() >= 3, "{replay:?}");
    for _ in 1..replay.len() {
        assert!(
            lines.next(wait).is_some(),
            "the tail fell behind:\n{}",
            lines.seen
        );
    }
    let _ = tail.kill();
    let _ = tail.wait();
    let tailed = events(&lines.seen);
    assert_eq!(
        tailed, replay,
        "the tail across the restart is exactly the replay"
    );
}
