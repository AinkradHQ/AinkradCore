//! The response path: a stream passes through as it arrives, a broken one never ends cleanly,
//! failures answer with a status and a code and nothing else, and the key is in no output.

use std::io;

use ainkrad_proto::redact::Redactor;
use tracing_subscriber::fmt::MakeWriter;

use super::*;

const LINE: &str = "POST /v1/messages HTTP/1.1";
const CHUNKED_HEAD: &str =
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";

fn chunk(data: &str) -> Vec<u8> {
    format!("{:x}\r\n{data}\r\n", data.len()).into_bytes()
}

async fn read_until(c: &mut UnixStream, acc: &mut Vec<u8>, needle: &str) {
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(acc).contains(needle) {
        let n = timeout(Duration::from_secs(5), c.read(&mut buf))
            .await
            .expect("the gateway sent nothing: the stream is buffered")
            .unwrap();
        assert!(n > 0, "the stream ended before {needle:?}");
        acc.extend_from_slice(&buf[..n]);
    }
}

#[tokio::test]
async fn an_sse_stream_reaches_the_agent_as_it_arrives_and_ends_with_its_last_chunk() {
    let gate = Arc::new(Notify::new());
    let mut first = CHUNKED_HEAD.as_bytes().to_vec();
    first.extend(chunk("data: one\n\n"));
    let mut rest = chunk("data: two\n\n");
    rest.extend_from_slice(b"0\r\n\r\n");
    let r = rig(Opts::anthropic(vec![
        Step::Send(first),
        Step::Wait(gate.clone()),
        Step::Send(rest),
        Step::Close,
    ]))
    .await;
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    c.write_all(&request(LINE, &[], &model_body()))
        .await
        .unwrap();
    let mut got = Vec::new();
    // The first event is here while the upstream is still holding the second back.
    read_until(&mut c, &mut got, "data: one").await;
    assert!(!String::from_utf8_lossy(&got).contains("data: two"));
    gate.notify_one();
    c.read_to_end(&mut got).await.unwrap();
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    );
    assert!(text.contains("content-type: text/event-stream"));
    assert!(text.ends_with("\r\n0\r\n\r\n"), "no last chunk: {text:?}");
    assert!(text.contains("data: two"));
}

#[tokio::test]
async fn a_stream_that_breaks_never_ends_cleanly() {
    // Cut with no close_notify, mid-chunk, after a short length, past the ceiling, and a bad chunk.
    let mut one = CHUNKED_HEAD.as_bytes().to_vec();
    one.extend(chunk("data: one\n\n"));
    let mut cut = one.clone();
    cut.extend_from_slice(b"20\r\npartial");
    let mut bad = one.clone();
    bad.extend_from_slice(b"zz\r\n");
    for (script, ceiling) in [
        (vec![Step::Send(one.clone()), Step::Abrupt], 1024),
        (vec![Step::Send(one.clone()), Step::Close], 1024),
        (vec![Step::Send(cut), Step::Close], 1024),
        (vec![Step::Send(bad), Step::Close], 1024),
        // Longer than the response ceiling: cut, and said so by never finishing.
        (
            vec![Step::Send({
                let mut v = CHUNKED_HEAD.as_bytes().to_vec();
                v.extend(chunk(&"x".repeat(200)));
                v.extend_from_slice(b"0\r\n\r\n");
                v
            })],
            50,
        ),
    ] {
        let mut o = Opts::anthropic(script);
        o.limits = Some((1024, ceiling));
        let r = rig(o).await;
        let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(
            !text.ends_with("0\r\n\r\n"),
            "a broken stream ended cleanly: {text:?}"
        );
    }
    // A length-framed body that comes up short is short, and a close-framed one that is
    // truncated has no clean end either.
    let r = rig(Opts::anthropic(vec![
        Step::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789".to_vec()),
        Step::Abrupt,
    ]))
    .await;
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert!(
        body_of(&resp).len() < 100,
        "{}",
        String::from_utf8_lossy(&resp)
    );
    let r = rig(Opts::anthropic(vec![
        Step::Send(b"HTTP/1.1 200 OK\r\n\r\nhello".to_vec()),
        Step::Abrupt,
    ]))
    .await;
    let text = String::from_utf8_lossy(&raw(&r.sock, &request(LINE, &[], &model_body())).await)
        .into_owned();
    assert!(!text.ends_with("0\r\n\r\n"), "{text:?}");
    // The same body closed cleanly is a clean stream.
    let r = rig(Opts::anthropic(vec![
        Step::Send(b"HTTP/1.1 200 OK\r\n\r\nhello".to_vec()),
        Step::Close,
    ]))
    .await;
    let text = String::from_utf8_lossy(&raw(&r.sock, &request(LINE, &[], &model_body())).await)
        .into_owned();
    assert!(text.ends_with("5\r\nhello\r\n0\r\n\r\n"), "{text:?}");
}

/// Every log line the gateway writes, kept for the assertions.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl io::Write for Logs {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Logs {
    type Writer = Logs;

    fn make_writer(&'a self) -> Logs {
        self.clone()
    }
}

#[tokio::test]
async fn failures_say_a_status_and_a_code_and_the_key_is_in_no_response_log_or_debug() {
    let logs = Logs::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    );
    let mut all = Vec::new();
    let mut keys = Vec::new();

    // A success, a hostile upstream that echoes the key in its body, a refused address, a bad
    // certificate, an unreachable upstream, a bad response head, a stalled one cut by the deadline.
    let echo = |k: &str| {
        format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {0}\r\n\r\n{k}",
            k.len()
        )
        .into_bytes()
    };
    let k = key_of("sk-ant-");
    let r = rig(Opts::anthropic(vec![Step::Send(echo(&k))])).await;
    let ok = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    // Error bodies pass to the harness; the transcript redactor (below) is what masks them.
    assert_eq!(status(&ok), 401, "{}", String::from_utf8_lossy(&ok));
    keys.push(r.key.clone());
    all.push(("echoed body, 401", ok, true));

    let mut o = Opts::anthropic(ok_script());
    o.answers = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))];
    let r = rig(o).await;
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 502);
    assert!(body_of(&resp).contains("gateway_refused_address"));
    assert_eq!(r.up.count(), 0);
    keys.push(r.key.clone());
    all.push(("refused address", resp, false));

    let mut o = Opts::anthropic(ok_script());
    o.cert = "other.example.test".to_owned();
    let r = rig(o).await;
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 502);
    assert!(body_of(&resp).contains("gateway_tls_failed"));
    keys.push(r.key.clone());
    all.push(("bad certificate", resp, false));

    for (script, code) in [
        (
            vec![Step::Send(
                b"HTTP/1.1 200 OK\r\nbad header\r\n\r\n".to_vec(),
            )],
            "gateway_bad_upstream",
        ),
        (
            vec![Step::Send(b"HTTP/1.1 101 Switching\r\n\r\n".to_vec())],
            "gateway_bad_upstream",
        ),
        (vec![Step::Abrupt], "gateway_bad_upstream"),
    ] {
        let r = rig(Opts::anthropic(script)).await;
        let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
        assert_eq!(status(&resp), 502, "{}", String::from_utf8_lossy(&resp));
        assert!(
            body_of(&resp).contains(code),
            "{}",
            String::from_utf8_lossy(&resp)
        );
        keys.push(r.key.clone());
        all.push(("bad upstream", resp, false));
    }

    // Everything that was written anywhere, and the types that hold the key.
    let logged = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    assert!(!logged.is_empty(), "the capture saw no log line");
    for key in &keys {
        assert!(
            !logged.contains(key.as_str()),
            "the key is in a log line: {logged}"
        );
        let key_type = Key::new(Zeroizing::new(key.clone())).unwrap();
        assert_eq!(format!("{key_type:?}"), "Key(..)");
        let g = grant(
            Wire::AnthropicMessages,
            "api.anthropic.com",
            "",
            "anthropic",
        );
        assert!(!format!("{g:?}").contains(key.as_str()));
        for (what, resp, echoes) in &all {
            if !echoes {
                assert!(
                    !String::from_utf8_lossy(resp).contains(key.as_str()),
                    "{what} carried the key"
                );
            }
        }
    }
    // The body that echoes the key is what the session's redactor masks in the transcript.
    let mut redactor = Redactor::new();
    redactor.known("acct.anthropic.1", &k);
    assert!(
        !redactor
            .text(&String::from_utf8_lossy(&all[0].1))
            .contains(&k)
    );
}

#[tokio::test]
async fn a_lease_becomes_a_gateway_whose_slot_names_a_socket_and_never_the_key() {
    use crate::v2::agent::secrets::{Leased, Redeem};
    let key = key_of("sk-ant-");
    let value = key.clone();
    let redeem: Redeem = Arc::new(move |lease: String| {
        let value = value.clone();
        Box::pin(async move {
            if lease != "l_gw" {
                return Err("no such lease".to_owned());
            }
            Ok(Leased {
                name: "acct.anthropic.1".to_owned(),
                delivery: "gateway".to_owned(),
                value: Zeroizing::new(value),
                form: Default::default(),
            })
        })
    });
    let dir = std::env::temp_dir().join(format!("gw-sess-{}", std::process::id()));
    let mut g = grant(
        Wire::AnthropicMessages,
        "api.anthropic.com",
        "",
        "anthropic",
    );
    g.lease = "l_gw".to_owned();
    let mut redactor = Redactor::new();
    let (gw, env, _events) = super::super::session::open(&g, Some(&redeem), &dir, &mut redactor)
        .await
        .unwrap();
    let names: Vec<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "AINKRAD_SANDBOX_GW_SOCK",
            "AINKRAD_SANDBOX_GW_FWD",
            "AINKRAD_SANDBOX_GW_PORT"
        ]
    );
    assert!(env.iter().all(|(_, v)| !v.contains(&key)));
    let sock = &env[0].1;
    assert!(sock.ends_with("gateway.sock"));
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(sock).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600);
    // The redactor knows the key from here on.
    assert!(!redactor.text(&format!("leaked {key}")).contains(&key));
    drop(gw);
    assert!(
        !std::path::Path::new(sock).exists(),
        "the socket outlived the gateway"
    );

    // A wrong lease, a missing redeemer, and a key for another host fail without naming either.
    let mut bad = g.clone();
    bad.lease = "l_other".to_owned();
    let e = super::super::session::open(&bad, Some(&redeem), &dir, &mut redactor)
        .await
        .err()
        .unwrap();
    assert!(!e.contains(&key) && !e.contains("l_other"), "{e}");
    assert!(
        super::super::session::open(&g, None, &dir, &mut redactor)
            .await
            .is_err()
    );
    let mut other = g.clone();
    other.upstream.host = "api.openai.com".to_owned();
    other.provider = "openai".to_owned();
    let e = super::super::session::open(&other, Some(&redeem), &dir, &mut redactor)
        .await
        .err()
        .unwrap();
    assert!(!e.contains(&key), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}
