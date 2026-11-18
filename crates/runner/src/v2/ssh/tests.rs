//! `ssh.exec` against in-process `russh` servers: host-key checks before authentication, jump chains,
//! limits, the pool, refused algorithms, and no key bytes in any log or error.

use std::sync::Mutex;
use std::sync::atomic::Ordering::SeqCst;

use ainkrad_proto::v2::TRUNCATED_MARKER;
use russh::Preferred;
use russh::keys::ssh_key::LineEnding;

use super::super::exec::tests::{RUNNER_KEY, driver};
use super::fixture::*;
use super::*;

#[tokio::test]
async fn runs_a_command_and_returns_exit_code_and_both_pipes() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let r = ssh(&leases)
        .run(&req(s.hop("me", "l_1"), vec![], "both"), never())
        .await
        .unwrap();
    assert_eq!(
        (text(&r), r.stderr.text.as_str(), r.exit_code),
        ("out\n", "oops\n", Some(3))
    );
    assert!(!r.timed_out);
}

#[tokio::test]
async fn a_wrong_host_key_aborts_before_any_authentication() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let mut hop = s.hop("me", "l_1");
    hop.pinned_keys = vec![fp(&new_key())];
    let e = ssh(&leases)
        .run(&req(hop, vec![], "name"), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::HostKeyChanged);
    let seen = e.host_key.unwrap();
    assert_eq!((seen.hop, seen.fingerprint), (0, fp(&s.host_key)));
    assert_eq!(s.seen.auth.load(SeqCst), 0, "the server saw authentication");
}

#[tokio::test]
async fn an_unpinned_host_is_unknown_with_its_fingerprint_and_nothing_authenticated() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let mut hop = s.hop("me", "l_1");
    hop.pinned_keys.clear();
    let e = ssh(&leases)
        .run(&req(hop, vec![], "name"), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::HostKeyUnknown);
    assert_eq!(e.host_key.unwrap().fingerprint, fp(&s.host_key));
    assert_eq!(s.seen.auth.load(SeqCst), 0);
}

#[tokio::test]
async fn a_three_hop_chain_runs_on_the_target_and_four_hops_are_refused() {
    let leases = Leases::default();
    let hops = [
        serve("J1", true).await,
        serve("J2", true).await,
        serve("J3", true).await,
        serve("J4", true).await,
    ];
    let target = serve("T", true).await;
    for l in ["l_1", "l_2", "l_3", "l_4", "l_t"] {
        leases.key(l);
    }
    let jumps: Vec<SshHop> = hops
        .iter()
        .enumerate()
        .map(|(i, s)| s.hop("j", &format!("l_{}", i + 1)))
        .collect();
    let d = ssh(&leases);
    let r = d
        .run(
            &req(target.hop("me", "l_t"), jumps[..3].to_vec(), "name"),
            never(),
        )
        .await
        .unwrap();
    assert_eq!(text(&r), "T\n");
    // Each jump carried exactly the next hop.
    let carried: Vec<_> = hops[..3]
        .iter()
        .map(|s| s.seen.forwards.load(SeqCst))
        .collect();
    assert_eq!(carried, [1, 1, 1]);

    let before = leases.redeemed.load(SeqCst);
    let e = d
        .run(&req(target.hop("me", "l_t"), jumps, "name"), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert_eq!(leases.redeemed.load(SeqCst), before, "a lease was redeemed");
    assert_eq!(hops[3].seen.conns.load(SeqCst), 0);
}

#[tokio::test]
async fn a_changed_key_on_a_jump_stops_the_chain_before_the_next_hop() {
    let (leases, j, t) = (
        Leases::default(),
        serve("J", true).await,
        serve("T", true).await,
    );
    for l in ["l_j", "l_t"] {
        leases.key(l);
    }
    let mut jump = j.hop("j", "l_j");
    jump.pinned_keys = vec![fp(&new_key())];
    let e = ssh(&leases)
        .run(&req(t.hop("me", "l_t"), vec![jump], "name"), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::HostKeyChanged);
    assert_eq!(e.host_key.unwrap().hop, 0);
    assert_eq!(
        (j.seen.auth.load(SeqCst), t.seen.conns.load(SeqCst)),
        (0, 0)
    );
}

#[tokio::test]
async fn a_host_that_refuses_the_key_is_an_auth_failure() {
    let (leases, s) = (Leases::default(), serve("T", false).await);
    leases.key("l_1");
    let e = ssh(&leases)
        .run(&req(s.hop("me", "l_1"), vec![], "name"), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::SshAuthFailed);
}

#[tokio::test]
async fn an_output_flood_is_capped_counted_and_marked() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let mut r = req(s.hop("me", "l_1"), vec![], "flood");
    r.limits.max_output_bytes = Some(1000);
    let r = ssh(&leases).run(&r, never()).await.unwrap();
    assert_eq!(r.stdout.bytes, 160 * 32 * 1024);
    assert!(r.stdout.truncated && r.stdout.text.ends_with(TRUNCATED_MARKER));
    assert!(r.stdout.text.len() <= 1000 + TRUNCATED_MARKER.len());
}

#[tokio::test]
async fn output_is_redacted_and_a_slow_command_times_out() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let d = ssh(&leases);
    let r = d
        .run(&req(s.hop("me", "l_1"), vec![], "secret"), never())
        .await
        .unwrap();
    assert!(!text(&r).contains(RUNNER_KEY) && text(&r).contains("[redacted:"));
    let mut slow = req(s.hop("me", "l_1"), vec![], "sleep");
    slow.limits.timeout_ms = Some(300);
    let r = d.run(&slow, never()).await.unwrap();
    assert!(r.timed_out && r.exit_code.is_none());
}

#[tokio::test]
async fn capacity_is_the_exec_drivers() {
    let leases = Leases::default();
    let d = SshDriver::new(Arc::new(driver(1)), leases.redeem());
    let _held = d.slot().unwrap();
    assert_eq!(d.slot().unwrap_err().code, ErrorCode::Busy);
    let commands = d.info().unwrap().commands;
    assert_eq!(commands[0], OP_SSH_EXEC);
    // ... the sftp ops (Y2-03), all of them, the Mac-direct agent pair (Y6-01), and the feature flag of
    // interactive terminals (Y2-02).
    assert_eq!(commands.len(), 1 + 7 + 2 + 1);
    assert!(commands[1..8].iter().all(|c| c.starts_with("ssh.sftp.")));
    assert!(commands[8..10].iter().all(|c| c.starts_with("ssh.agent.")));
    assert_eq!(commands[10], FEATURE_PTY_SSH);
}

#[tokio::test]
async fn a_connection_is_pooled_per_key_and_closed_when_idle() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    leases.key("l_2");
    let d = ssh(&leases).with_idle(Duration::from_millis(400));
    let go = |lease: &str| req(s.hop("me", lease), vec![], "name");
    d.run(&go("l_1"), never()).await.unwrap();
    d.run(&go("l_1"), never()).await.unwrap();
    assert_eq!(
        s.seen.conns.load(SeqCst),
        1,
        "the second op did not reuse it"
    );
    // Another key is another connection, even to the same host.
    d.run(&go("l_2"), never()).await.unwrap();
    assert_eq!(s.seen.conns.load(SeqCst), 2);
    // A pin that no longer lists the key it presented ends reuse.
    let mut moved = go("l_1");
    moved.target.pinned_keys = vec![fp(&new_key())];
    assert_eq!(
        d.run(&moved, never()).await.unwrap_err().code,
        ErrorCode::HostKeyChanged
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    d.run(&go("l_1"), never()).await.unwrap();
    assert_eq!(s.seen.conns.load(SeqCst), 4, "an idle connection was kept");
}

#[tokio::test]
async fn sha1_kex_and_sha1_host_keys_are_refused() {
    let leases = Leases::default();
    leases.key("l_1");
    // A server that only speaks SHA-1 key exchange.
    let config = russh::server::Config {
        keys: vec![new_key()],
        preferred: Preferred {
            kex: Cow::Borrowed(&[russh::kex::DH_G14_SHA1]),
            ..Preferred::DEFAULT
        },
        ..Default::default()
    };
    let s = start("T", true, config).await;
    let e = ssh(&leases)
        .run(&req(s.hop("me", "l_1"), vec![], "name"), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::SshFailed);
    assert_eq!(s.seen.auth.load(SeqCst), 0);
    // The client never offers SHA-1, CBC or DSA of any kind.
    let c = super::config(false);
    let names: Vec<String> = c
        .preferred
        .key
        .iter()
        .map(ToString::to_string)
        .chain(c.preferred.kex.iter().map(|n| format!("{n:?}")))
        .chain(c.preferred.cipher.iter().map(|n| format!("{n:?}")))
        .chain(c.preferred.mac.iter().map(|n| format!("{n:?}")))
        .collect();
    for n in &names {
        assert!(
            !["ssh-rsa", "ssh-dss", "sha1", "cbc", "3des"]
                .iter()
                .any(|bad| n == bad || n.contains(bad)),
            "offered {n}"
        );
    }
    assert!(names.iter().any(|n| n == "ssh-ed25519"), "{names:?}");
    assert!(c.preferred.key.iter().all(|a| a.as_str() != "ssh-dss"));
}

/// Log lines and records: `tracing` and the `log` crate russh uses.
static LOG: Mutex<String> = Mutex::new(String::new());

struct Capture;
impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        LOG.lock().unwrap().push_str(&format!("{}\n", r.args()));
    }
    fn flush(&self) {}
}

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
    type Writer = Sink;
    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

#[tokio::test]
async fn key_bytes_are_in_no_log_error_or_result() {
    static CAPTURE: Capture = Capture;
    let _ = log::set_logger(&CAPTURE);
    log::set_max_level(log::LevelFilter::Trace);
    let sink = Sink::default();
    // (see login/redact_tests: a second dispatcher keeps tracing from caching `never`.)
    let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let _g = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(sink.clone())
            .finish(),
    );
    let leases = Leases::default();
    let key = leases.key("l_good");
    let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
    // A lease whose value is garbage carrying a marker: the parse error must not echo it.
    leases.add("l_bad", "SEEDED-GARBAGE-SECRET-0123456789");
    let (ok, refuse) = (serve("T", true).await, serve("T", false).await);
    let mut shown = Vec::new();
    let d = ssh(&leases);
    let mut unknown = ok.hop("me", "l_good");
    unknown.pinned_keys.clear();
    for r in [
        req(ok.hop("me", "l_good"), vec![], "name"),
        req(unknown, vec![], "name"),
        req(refuse.hop("me", "l_good"), vec![], "name"),
        req(ok.hop("me", "l_bad"), vec![], "name"),
    ] {
        shown.push(format!("{:?}", d.run(&r, never()).await));
    }
    assert!(shown[0].contains("Ok(") && shown[3].contains("SshAuthFailed"));

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&pem);
    let mut secrets = vec![pem.clone(), b64, "SEEDED-GARBAGE-SECRET".to_owned()];
    secrets.extend(
        pem.lines()
            .filter(|l| l.len() > 30 && !l.contains("-----"))
            .map(String::from),
    );
    // The private scalar itself, in the encodings a careless log would use.
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    secrets.push(seed.iter().map(|b| format!("{b:02x}")).collect());
    secrets.push(base64::engine::general_purpose::STANDARD.encode(seed));
    let haystack = format!(
        "{}\n{}\n{}",
        String::from_utf8_lossy(&sink.0.lock().unwrap()),
        LOG.lock().unwrap(),
        shown.join("\n")
    );
    assert!(haystack.len() > 500, "nothing was captured: {haystack}");
    for s in secrets {
        assert!(!haystack.contains(&s), "key material in the logs: {s:.12}");
    }
}

/// Y2-01 integration against real OpenSSH servers in Podman (`#[ignore]`: it needs them). The setup
/// exports `LEYLINE_IT_*`. Run: `cargo test -p ainkrad-runner --lib -- --ignored real_openssh`.
#[tokio::test]
#[ignore = "needs throwaway OpenSSH containers (LEYLINE_IT_*)"]
async fn real_openssh_exec_trust_jump_and_refused_algorithms() {
    let env = |k: &str| std::env::var(format!("LEYLINE_IT_{k}")).unwrap_or_else(|_| panic!("{k}"));
    let port = |k: &str| env(k).parse::<u16>().unwrap();
    let read = |k: &str| std::fs::read_to_string(env(k)).unwrap();
    let leases = Leases::default();
    leases.add("l_ed", &read("KEY"));
    let hop = |p: u16, host: &str, pins: &[&str], lease: &str| SshHop {
        host: host.to_owned(),
        port: p,
        user: "it".to_owned(),
        pinned_keys: pins.iter().map(ToString::to_string).collect(),
        lease: lease.to_owned(),
    };
    let d = ssh(&leases);
    let local = "127.0.0.1";

    // First contact: unknown, and the fingerprint is what OpenSSH itself prints for that host.
    let first = req(hop(port("A"), local, &[], "l_ed"), vec![], "id -un");
    let e = d.run(&first, never()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::HostKeyUnknown);
    let seen = e.host_key.unwrap().fingerprint;
    assert_eq!(seen, env("A_FP"));
    // Pinned: output, stderr, exit code.
    let a = hop(port("A"), local, &[&seen], "l_ed");
    let run = "printf 'user=%s\\n' \"$(id -un)\"; echo err >&2; exit 5";
    let r = d.run(&req(a.clone(), vec![], run), never()).await.unwrap();
    let got = (text(&r), r.stderr.text.as_str(), r.exit_code);
    assert_eq!(got, ("user=it\n", "err\n", Some(5)));
    // A different pin: refused as changed.
    let wrong = hop(port("A"), local, &[&fp(&new_key())], "l_ed");
    let e = d.run(&req(wrong, vec![], "id"), never()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::HostKeyChanged);
    // Through a real jump host: B carries the connection to A by its container name.
    let b = hop(port("B"), local, &[&env("B_FP")], "l_ed");
    let via = hop(2222, "leyline-it-a", &[&seen], "l_ed");
    let r = d
        .run(&req(via, vec![b], "hostname"), never())
        .await
        .unwrap();
    assert_eq!(text(&r), "leyline-it-a\n");
    // Flood and timeout under the same limits as exec.run.
    let mut flood = req(a.clone(), vec![], "head -c 5000000 /dev/zero | tr '\\0' A");
    flood.limits.max_output_bytes = Some(1000);
    let r = d.run(&flood, never()).await.unwrap();
    assert_eq!((r.stdout.bytes, r.stdout.truncated), (5_000_000, true));
    let mut slow = req(a, vec![], "sleep 30");
    slow.limits.timeout_ms = Some(500);
    assert!(d.run(&slow, never()).await.unwrap().timed_out);
    // A server that only offers `ssh-rsa` (SHA-1) is refused, with nothing authenticated.
    let sha1 = hop(port("C"), local, &[&env("C_FP")], "l_ed");
    let e = d.run(&req(sha1, vec![], "id"), never()).await.unwrap_err();
    // (Not "cannot connect": the server is up, and no algorithm is common.)
    assert_eq!(e.code, ErrorCode::SshFailed, "{e:?}");
    assert!(e.message.contains("No common"), "{e:?}");
}
