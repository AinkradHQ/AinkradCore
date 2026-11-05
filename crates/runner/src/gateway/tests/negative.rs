//! What a hostile client or a hostile upstream can still try against the gateway (KAN-435 G8,
//! threats T6 to T9), beyond what the other files in this directory already hold: a head or a body
//! that never ends, framing and target variants, the provider-side extras of OpenRouter over the
//! wire, bodies built to exhaust the parser, the exact set of headers an upstream may see, and a
//! reply whose usage numbers are junk. Every refusal here happens before the upstream is dialled.

use ainkrad_proto::v2::Wire;

use super::*;

const LINE: &str = "POST /v1/messages HTTP/1.1";

/// A request written by hand, so a malformed one can be sent.
fn hand(lines: &[&str], body: &str) -> Vec<u8> {
    format!("{}\r\n\r\n{body}", lines.join("\r\n")).into_bytes()
}

/// Sends `bytes` and then nothing, and reads until the gateway ends the connection.
async fn stall(sock: &std::path::Path, bytes: &[u8]) -> Vec<u8> {
    let mut c = UnixStream::connect(sock).await.unwrap();
    c.write_all(bytes).await.unwrap();
    let mut out = Vec::new();
    let _ = timeout(Duration::from_secs(300), c.read_to_end(&mut out)).await;
    out
}

#[tokio::test(start_paused = true)]
async fn a_head_that_never_ends_or_arrives_a_byte_at_a_time_is_cut_off_and_never_dialled() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let t0 = tokio::time::Instant::now();
    let resp = stall(&r.sock, b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n").await;
    assert_eq!(status(&resp), 400, "{}", String::from_utf8_lossy(&resp));
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_secs(10) && took < Duration::from_secs(30),
        "{took:?}"
    );
    // A drip never resets the clock: the bound is on the whole head.
    let t0 = tokio::time::Instant::now();
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    for _ in 0..8 {
        if c.write_all(b"a").await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
    let mut out = Vec::new();
    let _ = timeout(Duration::from_secs(300), c.read_to_end(&mut out)).await;
    assert_eq!(status(&out), 400);
    assert!(t0.elapsed() < Duration::from_secs(40), "{:?}", t0.elapsed());
    assert_eq!(r.up.count(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_body_that_never_arrives_is_cut_off_and_gives_its_permit_back() {
    let mut o = Opts::anthropic(ok_script());
    o.grant.rate.concurrent = 1;
    let r = rig(o).await;
    let sock = r.sock.clone();
    // A length of 100 and twelve bytes of it, then silence.
    let slow = tokio::spawn(async move {
        stall(
            &sock,
            b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{\"model\":\"m\"",
        )
        .await
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    // While it holds the one permit, the next request is turned away and nothing is dialled.
    let busy = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&busy), 429);
    assert!(body_of(&busy).contains("gateway_busy"));
    let resp = slow.await.unwrap();
    assert_eq!(status(&resp), 400, "{}", String::from_utf8_lossy(&resp));
    // The permit is back: a request now gets past it to the model check (a 403, not a 429).
    let next = raw(&r.sock, &request(LINE, &[], "{\"model\":\"other\"}")).await;
    assert_eq!(status(&next), 403);
    assert_eq!(r.up.count(), 0);
}

#[tokio::test]
async fn more_framing_and_target_variants_are_refused_before_the_upstream() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let b = model_body();
    let cl = format!("Content-Length: {}", b.len());
    let cases: Vec<(Vec<u8>, u16)> = vec![
        // The same length twice under different capitalisation; a list of lengths.
        (hand(&[LINE, "Host: x", &cl, &cl.to_lowercase()], &b), 400),
        (
            hand(
                &[
                    LINE,
                    "Host: x",
                    &format!("Content-Length: {0}, {0}", b.len()),
                ],
                &b,
            ),
            400,
        ),
        // A transfer coding in capitals, next to a length and on its own.
        (
            hand(&[LINE, "Host: x", &cl, "TRANSFER-ENCODING: chunked"], &b),
            400,
        ),
        (
            hand(
                &[
                    LINE,
                    "Host: x",
                    "TRANSFER-ENCODING: chunked",
                    "Expect: 100-continue",
                ],
                "0\r\n\r\n",
            ),
            411,
        ),
        // A length of nothing: an empty body is not a JSON object.
        (hand(&[LINE, "Host: x", "Content-Length: 0"], ""), 400),
        // A control byte in a value: DEL and SOH.
        (hand(&[LINE, "Host: x", &cl, "X-A: a\u{7f}b"], &b), 400),
        (hand(&[LINE, "Host: x", &cl, "X-A: a\u{1}b"], &b), 400),
        // An encoded line break in the target is not decoded into a header, and no other query
        // item, encoded or not, is on the route's list.
        (
            hand(
                &[
                    "POST /v1/messages?beta=true&x=%0d%0aHost:%20evil HTTP/1.1",
                    "Host: x",
                    &cl,
                ],
                &b,
            ),
            403,
        ),
        (
            hand(
                &["POST /v1/messages?beta=%74rue HTTP/1.1", "Host: x", &cl],
                &b,
            ),
            403,
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

/// An OpenRouter-style user provider whose grant also names `:online` and a second model.
async fn router_rig(script: Vec<Step>) -> Rig {
    let mut o = Opts::of(
        Wire::OpenaiResponses,
        "openrouter.example.test",
        "/api/v1",
        "openrouter",
        "sk-or-v1-",
        script,
    );
    o.grant.user_key = Some(user_def());
    for m in ["model-a:online", "model-b"] {
        o.grant.models.push(m.to_owned());
        let mut p = o.grant.prices[0].clone();
        p.model = m.to_owned();
        o.grant.prices.push(p);
    }
    rig(o).await
}

#[tokio::test]
async fn a_provider_side_web_search_plugin_or_fallback_route_is_refused_over_the_wire() {
    let r = router_rig(ok_script()).await;
    let cases: [(&str, &str); 8] = [
        (
            r#"{"model":"model-a","max_tokens":8,"plugins":[{"id":"web"}]}"#,
            "web_not_allowed",
        ),
        (
            r#"{"model":"model-a","max_tokens":8,"plugins":{"id":"file-parser"}}"#,
            "web_not_allowed",
        ),
        // The granted model carries the suffix: the allowlist passes it, the web check does not.
        (
            r#"{"model":"model-a:online","max_tokens":8}"#,
            "web_not_allowed",
        ),
        (
            r#"{"model":"model-a","max_tokens":8,"models":["model-b","model-a:ONLINE"]}"#,
            "web_not_allowed",
        ),
        // A fallback list may not route round the allowlist.
        (
            r#"{"model":"model-a","max_tokens":8,"models":["model-a","model-z"]}"#,
            "model_not_allowed",
        ),
        (
            r#"{"model":"model-a","max_tokens":8,"models":"model-b"}"#,
            "model_not_allowed",
        ),
        // A repeated key cannot hide the plugin from the check and show it to the provider.
        (
            r#"{"model":"model-a","max_tokens":8,"plugins":[{"id":"web"}],"plugins":[]}"#,
            "bad_json",
        ),
        (
            r#"{"model":"model-a","max_tokens":8,"models":["model-b"],"models":["model-z"]}"#,
            "bad_json",
        ),
    ];
    for (body, code) in cases {
        let resp = raw(
            &r.sock,
            &request("POST /v1/chat/completions HTTP/1.1", &[], body),
        )
        .await;
        assert!(
            matches!(status(&resp), 400 | 403) && body_of(&resp).contains(code),
            "{body}: {}",
            String::from_utf8_lossy(&resp)
        );
    }
    assert_eq!(r.up.count(), 0, "a refusal was dialled");
    // The same request without the extras, and with the empty and null forms, is served.
    for body in [
        r#"{"model":"model-a","max_tokens":8,"models":["model-b"],"plugins":[]}"#,
        r#"{"model":"model-a","max_tokens":8,"plugins":null}"#,
    ] {
        let resp = raw(
            &r.sock,
            &request("POST /v1/chat/completions HTTP/1.1", &[], body),
        )
        .await;
        assert_eq!(status(&resp), 200, "{body}");
    }
    assert_eq!(r.up.count(), 2);
    // `plugins` is refused on every wire, not only where OpenRouter is.
    let a = rig(Opts::anthropic(ok_script())).await;
    let resp = raw(
        &a.sock,
        &request(
            LINE,
            &[],
            r#"{"model":"model-a","max_tokens":8,"plugins":[{"id":"web"}]}"#,
        ),
    )
    .await;
    assert_eq!(status(&resp), 403);
    assert_eq!(a.up.count(), 0);
}

#[tokio::test]
async fn a_body_built_to_exhaust_the_parser_or_the_tool_walk_is_refused_not_followed() {
    let r = rig(Opts::anthropic(ok_script())).await;
    // Nesting far past the parser's own limit: a plain 400, no stack to overflow.
    let deep = format!(
        "{{\"model\":\"{MODEL}\",\"max_tokens\":8,\"x\":{}{}}}",
        "[".repeat(5000),
        "]".repeat(5000)
    );
    let resp = raw(&r.sock, &request(LINE, &[], &deep)).await;
    assert_eq!(status(&resp), 400, "{}", String::from_utf8_lossy(&resp));
    // Namespaces of tools nested past the walk's depth hide a function the harness would run:
    // refused, where a shallow one is served.
    let nested = |depth: usize| {
        let mut tool = String::from(r#"{"type":"function","name":"f"}"#);
        for _ in 0..depth {
            tool = format!(r#"{{"type":"namespace","tools":[{tool}]}}"#);
        }
        format!("{{\"model\":\"{MODEL}\",\"max_tokens\":8,\"tools\":[{tool}]}}")
    };
    let resp = raw(&r.sock, &request(LINE, &[], &nested(12))).await;
    assert_eq!(status(&resp), 403);
    assert!(body_of(&resp).contains("tool_not_allowed"));
    assert_eq!(r.up.count(), 0);
    assert_eq!(
        status(&raw(&r.sock, &request(LINE, &[], &nested(2))).await),
        200
    );
    assert_eq!(r.up.count(), 1);
}

#[tokio::test]
async fn an_upstream_sees_only_the_headers_the_gateway_builds_and_none_of_the_agents_credentials() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let hostile = [
        "x-api-key: placeholder",
        "Authorization: Bearer placeholder",
        "Authorization: Basic cGxhY2Vob2xkZXI=",
        "x-goog-api-key: placeholder",
        "Proxy-Authorization: Basic cGxhY2Vob2xkZXI=",
        "OpenAI-Organization: org-agent",
        "OpenAI-Project: proj-agent",
        "x-goog-user-project: agent",
        "Forwarded: for=agent-host",
        "Via: 1.1 agent",
        "X-Real-IP: agent-host",
        "TE: trailers",
        "Expect: 100-continue",
        "Origin: http://agent.test",
        "Referer: http://agent.test/",
        "Cookie: session=placeholder",
        "anthropic-version: 2023-06-01",
        "User-Agent: harness/1",
    ];
    let resp = raw(&r.sock, &request(LINE, &hostile, &model_body())).await;
    assert_eq!(status(&resp), 200, "{}", String::from_utf8_lossy(&resp));
    let head = r.up.head(0);
    let lower = head.to_ascii_lowercase();
    assert!(!lower.contains("placeholder"), "{head}");
    assert_eq!(head.matches(&r.key).count(), 1, "{head}");
    // Every header line is on the list the gateway builds from: nothing else got through.
    let allowed = [
        "host",
        "content-length",
        "content-type",
        "accept-encoding",
        "connection",
        "anthropic-version",
        "user-agent",
        "x-api-key",
    ];
    for line in lower.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        let name = line.split(':').next().unwrap();
        assert!(
            allowed.contains(&name),
            "{name} reached the upstream: {head}"
        );
    }
}

#[tokio::test]
async fn a_reply_with_junk_usage_numbers_never_wraps_the_meter_or_stops_the_gateway() {
    // The most a count can be: the meter saturates at the ceiling and refuses what follows,
    // where a wrapped sum would have reset the session's spend to nothing.
    let huge = format!(
        "{{\"usage\":{{\"input_tokens\":{0},\"output_tokens\":{0},\"cache_read_input_tokens\":{0},\"cache_creation_input_tokens\":{0}}}}}",
        u64::MAX
    );
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{huge}",
        huge.len()
    );
    let mut r = rig(Opts::anthropic(vec![Step::Send(reply.into_bytes())])).await;
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 200);
    let rep = r.report().await;
    assert_eq!(rep.kind, ainkrad_proto::v2::GatewayReportKind::Usage);
    assert!(r.meter().spent().0 >= 1_000_000, "{:?}", r.meter().spent());
    let again = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&again), 429);
    assert!(body_of(&again).contains("gateway_ceiling"));
    assert_eq!(r.up.count(), 1, "no spend after the ceiling");
    // Negative, fractional and text counts are not counts: the request is estimated, and the
    // gateway serves the next one.
    let junk = r#"{"usage":{"input_tokens":-5,"output_tokens":1.5,"cache_read_input_tokens":"9"}}"#;
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{junk}",
        junk.len()
    );
    let mut r = rig(Opts::anthropic(vec![Step::Send(reply.into_bytes())])).await;
    for _ in 0..2 {
        let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
        assert_eq!(status(&resp), 200);
        assert!(r.report().await.approximate);
    }
}
