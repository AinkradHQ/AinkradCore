//! Request framing and smuggling, size limits, the rate and concurrency caps, and the start-up
//! check. Every refusal here happens before the upstream is dialled.

use ainkrad_proto::v2::Wire;

use super::*;

const LINE: &str = "POST /v1/messages HTTP/1.1";

/// A request written by hand, so a malformed one can be sent.
fn hand(lines: &[&str], body: &str) -> Vec<u8> {
    format!("{}\r\n\r\n{body}", lines.join("\r\n")).into_bytes()
}

#[tokio::test]
async fn a_request_that_could_be_framed_two_ways_is_refused_whole() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let b = model_body();
    let cl = format!("Content-Length: {}", b.len());
    let cases: Vec<(Vec<u8>, u16)> = vec![
        // CL + TE, in either order and with a harmless-looking coding.
        (
            hand(&[LINE, "Host: x", &cl, "Transfer-Encoding: chunked"], &b),
            400,
        ),
        (
            hand(&[LINE, "Host: x", "Transfer-Encoding: chunked", &cl], &b),
            400,
        ),
        (
            hand(&[LINE, "Host: x", &cl, "Transfer-Encoding: identity"], &b),
            400,
        ),
        // A chunked request is not read at all.
        (
            hand(
                &[LINE, "Host: x", "Transfer-Encoding: chunked"],
                "0\r\n\r\n",
            ),
            411,
        ),
        (
            hand(&[LINE, "Host: x", "Transfer-Encoding: identity"], &b),
            411,
        ),
        // Two lengths, even equal; a length that is not plain digits.
        (hand(&[LINE, "Host: x", &cl, &cl], &b), 400),
        (hand(&[LINE, "Host: x", &cl, "Content-Length: 0"], &b), 400),
        (hand(&[LINE, "Host: x", "Content-Length: +5"], &b), 400),
        (hand(&[LINE, "Host: x", "Content-Length: 1e1"], &b), 400),
        (hand(&[LINE, "Host: x", "Content-Length: 0x10"], &b), 400),
        (hand(&[LINE, "Host: x", "Content-Length: "], &b), 400),
        (
            hand(
                &[LINE, "Host: x", "Content-Length: 99999999999999999999"],
                &b,
            ),
            400,
        ),
        (hand(&[LINE, "Host: x"], &b), 411),
        // obs-fold, a space before the colon, a bare LF, a bare CR, a NUL.
        (
            hand(&[LINE, "Host: x", &cl, "X-A: 1", " folded: 2"], &b),
            400,
        ),
        (hand(&[LINE, "Host: x", &cl, "X-A : 1"], &b), 400),
        (hand(&[LINE, "Host: x", &cl, "X-A: 1\nX-B: 2"], &b), 400),
        (hand(&[LINE, "Host: x", &cl, "X-A: 1\rX-B: 2"], &b), 400),
        (hand(&[LINE, "Host: x", &cl, "X-A: 1\0"], &b), 400),
        // Two hosts; a version that is not 1.1; extra or missing request-line parts.
        (hand(&[LINE, "Host: x", "Host: y", &cl], &b), 400),
        (
            hand(&["POST /v1/messages HTTP/1.0", "Host: x", &cl], &b),
            400,
        ),
        (hand(&["POST /v1/messages", "Host: x", &cl], &b), 400),
        (
            hand(&["POST  /v1/messages HTTP/1.1", "Host: x", &cl], &b),
            400,
        ),
        (
            hand(&["POST /v1/messages HTTP/1.1 x", "Host: x", &cl], &b),
            400,
        ),
        (
            hand(&["post /v1/messages HTTP/1.1", "Host: x", &cl], &b),
            400,
        ),
        // Absolute-form, `*`, a fragment, a raw non-ASCII byte in the target.
        (
            hand(
                &[
                    "POST http://api.anthropic.com/v1/messages HTTP/1.1",
                    "Host: x",
                    &cl,
                ],
                &b,
            ),
            400,
        ),
        (hand(&["POST * HTTP/1.1", "Host: x", &cl], &b), 400),
        (
            hand(&["POST /v1/messages#x HTTP/1.1", "Host: x", &cl], &b),
            400,
        ),
        (
            "POST /v1/messagé HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
                .as_bytes()
                .to_vec(),
            400,
        ),
        // CONNECT (authority-form) and the upgrade family.
        (
            hand(
                &["CONNECT api.anthropic.com:443 HTTP/1.1", "Host: x", &cl],
                &b,
            ),
            405,
        ),
        (
            hand(
                &[
                    "GET /v1/responses HTTP/1.1",
                    "Host: x",
                    "Upgrade: websocket",
                    "Connection: Upgrade",
                ],
                "",
            ),
            426,
        ),
        (hand(&[LINE, "Host: x", &cl, "Upgrade: h2c"], &b), 426),
        (
            hand(
                &[LINE, "Host: x", &cl, "Connection: keep-alive, Upgrade"],
                &b,
            ),
            426,
        ),
        // A header value that cannot be sent upstream (non-ASCII): refused, not forwarded.
        (
            hand(&[LINE, "Host: x", &cl, "User-Agent: caf\u{e9}"], &b),
            400,
        ),
        // A repeated allow-listed header is ambiguous.
        (
            hand(
                &[
                    LINE,
                    "Host: x",
                    &cl,
                    "anthropic-version: 1",
                    "anthropic-version: 2",
                ],
                &b,
            ),
            400,
        ),
    ];
    for (bytes, want) in cases {
        let resp = raw(&r.sock, &bytes).await;
        assert_eq!(
            status(&resp),
            want,
            "{:?} -> {}",
            String::from_utf8_lossy(&bytes),
            String::from_utf8_lossy(&resp)
        );
    }
    assert_eq!(r.up.count(), 0, "a refused request was dialled");
}

#[tokio::test]
async fn a_second_request_pipelined_behind_the_first_is_never_served() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let one = request(LINE, &[], &model_body());
    let mut two = one.clone();
    two.extend_from_slice(&one);
    let resp = String::from_utf8_lossy(&raw(&r.sock, &two).await).into_owned();
    assert_eq!(resp.matches("HTTP/1.1 ").count(), 1, "{resp}");
    assert_eq!(r.up.count(), 1);
}

#[tokio::test]
async fn the_head_and_the_body_are_bounded() {
    let mut o = Opts::anthropic(ok_script());
    o.limits = Some((64, 1024));
    let r = rig(o).await;
    let big = "a".repeat(20 * 1024);
    let long = request(LINE, &[&format!("x-a: {big}")], &model_body());
    assert_eq!(status(&raw(&r.sock, &long).await), 431);
    let many: Vec<String> = (0..80).map(|i| format!("x-h{i}: 1")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(
        status(&raw(&r.sock, &request(LINE, &many, &model_body())).await),
        400
    );
    // Over the body limit: refused on its length alone, before the body is read.
    let body = format!("{{\"model\":\"{MODEL}\",\"pad\":\"{}\"}}", "x".repeat(100));
    assert_eq!(status(&raw(&r.sock, &request(LINE, &[], &body)).await), 413);
    assert_eq!(r.up.count(), 0);
    // At the limit it goes through.
    let at = "{\"model\":\"model-a\"}";
    assert!(at.len() <= 64);
    assert_eq!(status(&raw(&r.sock, &request(LINE, &[], at)).await), 200);
}

#[tokio::test]
async fn the_rate_and_concurrency_caps_answer_429_without_dialling() {
    let mut o = Opts::anthropic(ok_script());
    o.grant.rate.per_minute = 2;
    let r = rig(o).await;
    for _ in 0..2 {
        assert_eq!(
            status(&raw(&r.sock, &request(LINE, &[], &model_body())).await),
            200
        );
    }
    let third = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&third), 429);
    assert!(
        String::from_utf8_lossy(&third).contains("retry-after: 5")
            || String::from_utf8_lossy(&third).contains("Retry-After: 5")
    );
    assert_eq!(r.up.count(), 2);

    // One in flight (held open by the upstream) and a second one refused.
    let gate = Arc::new(Notify::new());
    let mut o = Opts::anthropic(vec![
        Step::Wait(gate.clone()),
        Step::Send(OK_JSON.as_bytes().to_vec()),
    ]);
    o.grant.rate.concurrent = 1;
    let r = rig(o).await;
    let sock = r.sock.clone();
    let first = tokio::spawn(async move { raw(&sock, &request(LINE, &[], &model_body())).await });
    while r.up.count() == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let busy = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&busy), 429);
    gate.notify_one();
    assert_eq!(status(&first.await.unwrap()), 200);
    // The permit is back.
    gate.notify_one();
    assert_eq!(
        status(&raw(&r.sock, &request(LINE, &[], &model_body())).await),
        200
    );
}

#[test]
fn a_grant_that_the_key_rule_or_the_shape_checks_refuse_never_opens_a_gateway() {
    let dialer = || Arc::new(Dialer::new(vec![]));
    let key = |v: &str| Key::new(Zeroizing::new(v.to_owned())).unwrap();
    let good = || {
        grant(
            Wire::AnthropicMessages,
            "api.anthropic.com",
            "",
            "anthropic",
        )
    };
    let open = |g: &GatewayGrant, k: &str| Config::new(g, key(k), dialer()).err();
    assert_eq!(open(&good(), &key_of("sk-ant-")), None);
    // The key may go to its own host only.
    assert!(open(&good(), &key_of("sk-proj-")).is_some());
    assert!(
        open(
            &grant(Wire::OpenaiResponses, "api.anthropic.com", "/v1", "openai"),
            &key_of("sk-ant-")
        )
        .is_some()
    );
    assert!(
        open(
            &grant(
                Wire::AnthropicMessages,
                "evil.example.test",
                "",
                "anthropic"
            ),
            &key_of("sk-ant-")
        )
        .is_some()
    );
    let mut g = good();
    g.provider = "openai".into();
    assert!(open(&g, &key_of("sk-ant-")).is_some());
    // The shape of the upstream.
    for host in [
        "127.0.0.1",
        "0x7f000001",
        "api.anthropic.com.",
        "localhost",
        "API.anthropic.com",
    ] {
        assert!(
            open(
                &grant(Wire::AnthropicMessages, host, "", "anthropic"),
                &key_of("sk-ant-")
            )
            .is_some(),
            "{host}"
        );
    }
    for base in [
        "/", "v1", "/v1/", "/v1?x=1", "/v1/../x", "//v1", "/v%31", "/v1#",
    ] {
        assert!(
            open(
                &grant(
                    Wire::AnthropicMessages,
                    "api.anthropic.com",
                    base,
                    "anthropic"
                ),
                &key_of("sk-ant-")
            )
            .is_some(),
            "{base}"
        );
    }
    let mut g = good();
    g.upstream.auth = ainkrad_proto::v2::GatewayAuth::Bearer;
    assert!(open(&g, &key_of("sk-ant-")).is_some());
    let mut g = good();
    g.rate.concurrent = 0;
    assert!(open(&g, &key_of("sk-ant-")).is_some());
    // A value that cannot sit in a header is not a key.
    for bad in ["", "a b", "a\r\nb", "caf\u{e9}"] {
        assert!(Key::new(Zeroizing::new(bad.to_owned())).is_err(), "{bad:?}");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_self_test_refuses_clearly_when_a_sessions_socket_path_would_not_fit() {
    // The real bubblewrap run is `tests/gateway_netns.rs`; this needs none, because the length of
    // a real session's path is checked first.
    let long = std::path::PathBuf::from(format!("/{}", "a".repeat(90)));
    let why = super::super::selftest(&long, std::path::Path::new("/nonexistent"))
        .await
        .unwrap_err();
    assert!(why.contains("shorter state directory"), "{why}");
}

#[tokio::test]
async fn dropping_the_gateway_closes_its_socket() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let sock = r.sock.clone();
    assert!(UnixStream::connect(&sock).await.is_ok());
    drop(r);
    assert!(UnixStream::connect(&sock).await.is_err());
}
