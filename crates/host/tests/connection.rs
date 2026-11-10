//! The order on a connection: peer first, then the deadline and the size caps, then the parse.
mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use common::*;

#[test]
fn a_wrong_peer_uid_is_refused_before_a_byte_is_read() {
    let mut fx = Fx::new();
    fx.ctx.ainkrad_uid = Some(ainkrad_sys::getuid() + 1);
    let req = fx.line(&fx.id(), "status", "{}");
    let (out, read) = fx.raw(&req, true);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        (v["ok"].clone(), v["code"].clone()),
        (false.into(), "forbidden_peer".into())
    );
    assert_eq!(
        v["id"],
        serde_json::Value::Null,
        "an unvetted peer's id is not echoed"
    );
    assert_eq!(read, 0, "nothing was read");
    assert!(fx.fake.calls.lock().unwrap().is_empty(), "nothing was run");
    assert!(
        fx.log().contains("refused - peer="),
        "the refusal is logged: {}",
        fx.log()
    );
    assert!(fx.log().contains("code=forbidden_peer"));

    // Sending nothing at all gets the same answer.
    let (out, read) = fx.raw(b"", false);
    assert!(String::from_utf8_lossy(&out).contains("forbidden_peer"));
    assert_eq!(read, 0);
}

#[test]
fn no_ainkrad_user_refuses_everyone() {
    let mut fx = Fx::new();
    fx.ctx.ainkrad_uid = None;
    let v = fx.send(&fx.line(&fx.id(), "status", "{}"));
    assert_eq!(v["code"], "forbidden_peer");
    assert_eq!(
        ainkrad_host::uid_in("ainkrad:x:0:0::/:/bin/sh\n", "ainkrad"),
        None,
        "uid 0 never counts"
    );
}

#[test]
fn the_ainkrad_uid_comes_from_passwd_by_exact_name() {
    let pw = "root:x:0:0::/root:/bin/sh\nainkrad2:x:5:5::/:/bin/false\nainkrad:x:998:998::/var/lib/ainkrad:/usr/sbin/nologin\nainkrad:x:7:7::/:/bin/false\nbad\n";
    assert_eq!(
        ainkrad_host::uid_in(pw, "ainkrad"),
        Some(998),
        "first line wins"
    );
    assert_eq!(ainkrad_host::uid_in(pw, "mallory"), None);
    assert_eq!(
        ainkrad_host::uid_in("ainkrad:x:abc:1::/:/bin/sh", "ainkrad"),
        None
    );
}

#[test]
fn an_oversized_line_is_refused_and_only_a_bounded_amount_is_read() {
    let fx = Fx::new();
    let pad = |n: usize| format!(r#"{{"v":1,"pad":"{}"}}"#, "x".repeat(n)).into_bytes();
    let mut line = pad(5000);
    line.truncate(4097);
    let (out, read) = fx.raw(&line, true);
    assert!(String::from_utf8_lossy(&out).contains("bad_request"));
    assert!(read <= 4098, "read {read}");
    // No newline at all: still bounded.
    let (out, read) = fx.raw(&vec![b'a'; 100_000], false);
    assert!(String::from_utf8_lossy(&out).contains("bad_request"));
    assert!(read <= 4098, "read {read}");
}

#[test]
fn two_lines_a_bad_encoding_and_an_early_eof_are_refused() {
    let fx = Fx::new();
    let one = fx.line(&fx.id(), "status", "{}");
    let mut two = one.clone();
    two.push(b'\n');
    two.extend_from_slice(&one);
    for (bytes, nl) in [
        (two, true),
        (vec![0xff, 0xfe, b'{'], true),
        (one.clone(), false),
        (b"".to_vec(), true),
    ] {
        let (out, _) = fx.raw(&bytes, nl);
        assert!(
            String::from_utf8_lossy(&out).contains("bad_request"),
            "{}",
            String::from_utf8_lossy(&out)
        );
    }
    assert!(fx.fake.calls.lock().unwrap().is_empty());
    // And the same request, well formed, works.
    assert_eq!(fx.call("status", "{}")["ok"], true);
}

#[test]
fn a_slow_loris_is_cut_off_at_the_two_second_deadline() {
    let fx = Fx::new();
    let (client, server) = UnixStream::pair().unwrap();
    let started = Instant::now();
    std::thread::scope(|s| {
        let h = s.spawn(|| ainkrad_host::serve(&fx.ctx, server));
        let mut c = &client;
        // One byte every 300 ms would keep a per-read timeout alive for ever.
        let t = s.spawn(move || {
            for b in b"{\"v\":1,\"id\":\"0123456789".iter() {
                if c.write_all(&[*b]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        let mut out = Vec::new();
        let mut r = &client;
        let _ = r.read_to_end(&mut out);
        assert!(String::from_utf8_lossy(&out).contains("bad_request"));
        h.join().unwrap();
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(1800) && took < Duration::from_millis(3200),
            "{took:?}"
        );
        drop(t);
    });
    assert!(fx.log().contains("code=bad_request"));
}

#[test]
fn every_refusal_is_answered_with_its_code_logged_and_changes_nothing() {
    let fx = Fx::new();
    let id = fx.id();
    let good = String::from_utf8(fx.line(&id, "status", "{}")).unwrap();
    let mut cases: Vec<(String, &str)> = vec![
        (good.replace("\"status\"", "\"nope\""), "unknown_action"),
        (good.replacen("{\"v\"", "{\"x\":1,\"v\"", 1), "bad_request"),
        (good.replace("\"v\":1", "\"v\":2"), "bad_request"),
        (good.replace("d_test-1", "root"), "bad_request"),
        (
            String::from_utf8(fx.line(&fx.id(), "logs", r#"{"unit":"core","lines":-1}"#)).unwrap(),
            "bad_request",
        ),
        (
            String::from_utf8(fx.line(&fx.id(), "logs", r#"{"unit":"core","before":"-r"}"#))
                .unwrap(),
            "bad_request",
        ),
        (
            String::from_utf8(fx.line(
                &fx.id(),
                "logs",
                r#"{"unit":"core","before":"--cursor-file=/etc/shadow"}"#,
            ))
            .unwrap(),
            "bad_request",
        ),
    ];
    for class_b in [
        "runner_policy",
        "install_tool",
        "update",
        "restore",
        "uninstall",
        "host_config",
        "add_owner",
        "remove_owner",
    ] {
        cases.push((
            String::from_utf8(fx.line(&fx.id(), class_b, r#"{"version":"9"}"#)).unwrap(),
            "unknown_action",
        ));
    }
    for (line, code) in &cases {
        let v = fx.send(line.as_bytes());
        assert_eq!(
            (v["ok"].clone(), v["code"].as_str()),
            (false.into(), Some(*code)),
            "{line}"
        );
        assert!(!v["message"].as_str().unwrap().contains("nope"));
    }
    let log = fx.log();
    assert_eq!(
        log.lines().filter(|l| l.contains(" refused ")).count(),
        cases.len(),
        "{log}"
    );
    assert_eq!(log.matches("class=b").count(), 8);
    assert!(
        !log.contains("shadow") && !log.contains("nope"),
        "request text is never logged"
    );
    assert!(
        fx.fake.calls.lock().unwrap().is_empty(),
        "no process was started"
    );
    assert!(!fx.state().join("limits.json").exists(), "no state changed");
}

#[test]
fn the_binary_refuses_a_peer_that_is_not_ainkrad() {
    // The real binary, the real SO_PEERCRED: this test process is not `ainkrad`.
    let (client, server) = UnixStream::pair().unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-host"))
        .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
            server,
        )))
        .stdout(std::process::Stdio::null())
        .env_clear()
        .spawn()
        .unwrap();
    let mut c = &client;
    let _ = c.write_all(b"{\"v\":1}\n");
    // One line is the whole answer; the helper closes with our bytes unread, so a read to EOF
    // would end in ECONNRESET after it (a client reads one line and stops).
    let mut out = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(c), &mut out).unwrap();
    assert!(out.contains(r#""code":"forbidden_peer""#), "{out}");
    assert!(child.wait().unwrap().success());
}
