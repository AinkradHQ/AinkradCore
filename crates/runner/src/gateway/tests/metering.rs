//! G4: usage becomes one report per request on the gateway's own channel, a request the ceiling
//! cannot cover is refused without contacting the upstream, a stream is cut at the ceiling, an
//! aborted stream is aborted and charged, and the body and header checks refuse what gives the
//! provider network reach.

use std::sync::atomic::AtomicBool;

use ainkrad_proto::v2::{Ceiling, GatewayReportKind, UpstreamStatus};

use super::*;

const LINE: &str = "POST /v1/messages HTTP/1.1";
const SSE_HEAD: &str =
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";

fn chunk(data: &str) -> Vec<u8> {
    format!("{:x}\r\n{data}\r\n", data.len()).into_bytes()
}

fn delta(text: &str) -> String {
    format!(
        "data: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"{text}\"}}}}\n\n"
    )
}

fn opts(script: Vec<Step>, tokens: u64) -> Opts {
    let mut o = Opts::anthropic(script);
    o.grant.ceiling = Ceiling {
        tokens,
        usd_micros: 1_000_000,
    };
    o
}

#[tokio::test]
async fn a_buffered_reply_ends_in_one_exact_usage_report_for_the_model_asked() {
    let body = r#"{"id":"m","usage":{"input_tokens":11,"output_tokens":5,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}"#;
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut r = rig(Opts::anthropic(vec![Step::Send(reply.into_bytes())])).await;
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 200);
    let rep = r.report().await;
    assert_eq!(rep.kind, GatewayReportKind::Usage);
    assert_eq!(rep.model.as_deref(), Some(MODEL));
    assert_eq!(
        (rep.input, rep.output, rep.cache_read, rep.cache_write),
        (11, 5, 3, 2)
    );
    assert!(!rep.approximate && rep.status == UpstreamStatus::Ok);
    assert!(r.no_report(), "exactly one report");
    assert_eq!(r.meter().spent().0, 21);
}

#[tokio::test]
async fn a_streamed_reply_split_anywhere_is_read_and_a_reply_without_usage_is_approximate() {
    let events = format!(
        "data: {{\"type\":\"message_start\",\"message\":{{\"usage\":{{\"input_tokens\":9,\"output_tokens\":1}}}}}}\n\n{}data: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":4}}}}\n\n",
        delta("hello")
    );
    let mut script = vec![Step::Send(SSE_HEAD.as_bytes().to_vec())];
    // One byte per chunk: lines are split across pieces everywhere.
    for b in events.as_bytes().chunks(1) {
        script.push(Step::Send(chunk(std::str::from_utf8(b).unwrap())));
    }
    script.push(Step::Send(b"0\r\n\r\n".to_vec()));
    let mut r = rig(Opts::anthropic(script)).await;
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert!(String::from_utf8_lossy(&resp).ends_with("0\r\n\r\n"));
    let rep = r.report().await;
    assert_eq!((rep.input, rep.output), (9, 4));
    assert!(!rep.approximate);

    // No usage anywhere: the characters / 4 stand in, and it is said.
    let mut script = vec![Step::Send(SSE_HEAD.as_bytes().to_vec())];
    script.push(Step::Send(chunk(&delta(&"x".repeat(40)))));
    script.push(Step::Send(b"0\r\n\r\n".to_vec()));
    let mut r = rig(Opts::anthropic(script)).await;
    raw(&r.sock, &request(LINE, &[], &model_body())).await;
    let rep = r.report().await;
    assert!(rep.approximate);
    assert_eq!(rep.output, 10);
}

#[tokio::test]
async fn a_request_the_ceiling_cannot_cover_is_refused_without_contacting_the_upstream() {
    // The body's bytes / 3 plus the 8 output tokens asked for do not fit in 10.
    let mut r = rig(opts(ok_script(), 10)).await;
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 429);
    assert!(body_of(&resp).contains("gateway_ceiling"));
    assert_eq!(r.up.count(), 0);
    assert!(r.no_report());
    // And once the limit is zero nothing is, whatever the room was.
    let r2 = rig(Opts::anthropic(ok_script())).await;
    r2.meter().set_ceiling(Ceiling {
        tokens: 0,
        usd_micros: 0,
    });
    let resp = raw(&r2.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 429);
    assert_eq!(r2.up.count(), 0);
}

#[tokio::test]
async fn concurrent_requests_are_bounded_by_what_the_ceiling_holds_for_each() {
    // One request's hold is about 22 tokens: 30 covers one, not two.
    let gate = Arc::new(Notify::new());
    let r = rig(opts(
        vec![
            Step::Send(SSE_HEAD.as_bytes().to_vec()),
            Step::Wait(gate.clone()),
        ],
        30,
    ))
    .await;
    let mut first = UnixStream::connect(&r.sock).await.unwrap();
    first
        .write_all(&request(LINE, &[], &model_body()))
        .await
        .unwrap();
    let mut got = Vec::new();
    read_head(&mut first, &mut got).await;
    let second = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&second), 429, "{}", String::from_utf8_lossy(&second));
    assert!(body_of(&second).contains("gateway_ceiling"));
    gate.notify_one();
}

async fn read_head(c: &mut UnixStream, acc: &mut Vec<u8>) {
    let mut buf = [0u8; 4096];
    while !acc.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = timeout(Duration::from_secs(5), c.read(&mut buf))
            .await
            .expect("no response head")
            .unwrap();
        assert!(n > 0, "closed before the head");
        acc.extend_from_slice(&buf[..n]);
    }
}

#[tokio::test]
async fn a_stream_is_cut_at_the_ceiling_and_charged_as_an_estimate() {
    // Room for the request's hold, but each event is 100 tokens of text: the cut comes.
    let gate = Arc::new(Notify::new());
    let mut script = vec![Step::Send(SSE_HEAD.as_bytes().to_vec())];
    for _ in 0..4 {
        script.push(Step::Send(chunk(&delta(&"y".repeat(400)))));
        script.push(Step::Wait(gate.clone()));
    }
    let mut r = rig(opts(script, 150)).await;
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    c.write_all(&request(LINE, &[], &model_body()))
        .await
        .unwrap();
    let mut got = Vec::new();
    let mut open = true;
    for _ in 0..4 {
        gate.notify_one();
        let mut buf = [0u8; 4096];
        match timeout(Duration::from_secs(5), c.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => {
                open = false;
                break;
            }
        }
    }
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(5), c.read_to_end(&mut rest)).await;
    got.extend(rest);
    let text = String::from_utf8_lossy(&got).into_owned();
    assert!(!text.ends_with("0\r\n\r\n"), "a cut stream ended cleanly");
    let _ = open;
    let rep = r.report().await;
    assert!(rep.approximate, "{rep:?}");
    assert!(rep.output >= 100, "{rep:?}");
    assert!(r.meter().spent().0 >= 100);
}

#[tokio::test]
async fn dropping_the_gateway_aborts_a_stream_in_flight_and_charges_it() {
    let closed = Arc::new(AtomicBool::new(false));
    let mut first = SSE_HEAD.as_bytes().to_vec();
    first.extend(chunk(&delta("hello world!")));
    let mut r = rig(Opts::anthropic(vec![
        Step::Send(first),
        Step::UntilClosed(closed.clone()),
    ]))
    .await;
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    c.write_all(&request(LINE, &[], &model_body()))
        .await
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains("hello world!") {
        let n = timeout(Duration::from_secs(5), c.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    r.close();
    // The harness's side ends, with no last chunk.
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(5), c.read_to_end(&mut rest)).await;
    got.extend(rest);
    assert!(!String::from_utf8_lossy(&got).ends_with("0\r\n\r\n"));
    // The upstream connection was closed by the gateway, not left open.
    for _ in 0..250 {
        if closed.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        closed.load(Ordering::SeqCst),
        "the upstream connection stayed open"
    );
    // And what had streamed is charged, as an estimate, exactly once.
    let rep = r.report().await;
    assert!(rep.approximate && rep.output >= 3, "{rep:?}");
    assert!(r.no_report());
    assert!(UnixStream::connect(&r.sock).await.is_err());
}

#[tokio::test]
async fn a_limit_of_zero_aborts_a_stream_that_is_idle_on_the_upstream() {
    let mut first = SSE_HEAD.as_bytes().to_vec();
    first.extend(chunk(&delta("abcd")));
    let mut r = rig(Opts::anthropic(vec![
        Step::Send(first),
        Step::Wait(Arc::new(Notify::new())), // never opened
    ]))
    .await;
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    c.write_all(&request(LINE, &[], &model_body()))
        .await
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains("abcd") {
        let n = timeout(Duration::from_secs(5), c.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    r.meter().set_ceiling(Ceiling {
        tokens: 0,
        usd_micros: 0,
    });
    let mut rest = Vec::new();
    timeout(Duration::from_secs(5), c.read_to_end(&mut rest))
        .await
        .expect("the stream stayed open after the limit")
        .unwrap();
    got.extend(rest);
    assert!(!String::from_utf8_lossy(&got).ends_with("0\r\n\r\n"));
    assert!(r.report().await.approximate);
}

#[tokio::test]
async fn upstream_signals_are_classes_with_a_retry_hint_and_never_text() {
    let cases: [(&str, UpstreamStatus, Option<u64>); 3] = [
        (
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\nContent-Length: 2\r\n\r\n{}",
            UpstreamStatus::RateLimited,
            Some(30),
        ),
        (
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}",
            UpstreamStatus::AuthFailed,
            None,
        ),
        (
            "HTTP/1.1 429 X\r\nContent-Length: 45\r\n\r\n{\"error\":{\"code\":\"insufficient_quota\",\"x\":1}}",
            UpstreamStatus::Quota,
            None,
        ),
    ];
    for (reply, want, retry) in cases {
        let mut r = rig(Opts::anthropic(vec![Step::Send(reply.as_bytes().to_vec())])).await;
        raw(&r.sock, &request(LINE, &[], &model_body())).await;
        let rep = r.report().await;
        assert_eq!(rep.kind, GatewayReportKind::Upstream);
        assert_eq!((rep.status, rep.retry_after), (want, retry));
        assert_eq!((rep.input, rep.output), (0, 0));
        assert_eq!(r.meter().spent(), (0, 0), "an error is not spend");
    }
    // A bad certificate and a refused address never reach an upstream.
    let mut o = Opts::anthropic(ok_script());
    o.cert = "other.example.test".to_owned();
    let mut r = rig(o).await;
    raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(r.report().await.status, UpstreamStatus::TlsFailed);
    let mut o = Opts::anthropic(ok_script());
    o.answers = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))];
    let mut r = rig(o).await;
    raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(r.report().await.status, UpstreamStatus::RefusedAddress);
}

#[tokio::test]
async fn requests_that_give_the_provider_network_reach_are_refused() {
    let r = rig(Opts::anthropic(ok_script())).await;
    for tools in [
        r#","tools":[{"type":"web_search_20250305","name":"web_search"}]"#,
        r#","tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]"#,
        r#","mcp_servers":[{"type":"url","url":"u","name":"n"}]"#,
        r#","tools":[{"type":"mcp_toolset","mcp_server_name":"n"}]"#,
    ] {
        let body = format!("{{\"model\":\"{MODEL}\",\"max_tokens\":8{tools}}}");
        let resp = raw(&r.sock, &request(LINE, &[], &body)).await;
        assert_eq!(status(&resp), 403, "{body}");
        assert!(body_of(&resp).contains("tool_not_allowed"));
    }
    assert_eq!(r.up.count(), 0);
    // An ordinary tool passes.
    let body = format!(
        "{{\"model\":\"{MODEL}\",\"max_tokens\":8,\"tools\":[{{\"name\":\"bash\",\"input_schema\":{{}}}}]}}"
    );
    assert_eq!(status(&raw(&r.sock, &request(LINE, &[], &body)).await), 200);
    // The other wires: OpenAI web search and remote MCP, Gemini grounding.
    let o = Opts::of(
        Wire::OpenaiResponses,
        "api.openai.com",
        "/v1",
        "openai",
        "sk-proj-",
        ok_script(),
    );
    let r = rig(o).await;
    for tools in [
        r#""tools":[{"type":"web_search"}]"#,
        r#""tools":[{"type":"mcp"}]"#,
    ] {
        let body = format!("{{\"model\":\"{MODEL}\",{tools}}}");
        let resp = raw(&r.sock, &request("POST /v1/responses HTTP/1.1", &[], &body)).await;
        assert_eq!(status(&resp), 403, "{body}");
    }
    let o = Opts::of(
        Wire::GeminiGenerate,
        "generativelanguage.googleapis.com",
        "",
        "google",
        "AIza",
        ok_script(),
    );
    let r = rig(o).await;
    for tool in [r#"{"google_search":{}}"#, r#"{"urlContext":{}}"#] {
        let body = format!("{{\"tools\":[{tool}]}}");
        let line = format!("POST /v1beta/models/{MODEL}:generateContent HTTP/1.1");
        assert_eq!(
            status(&raw(&r.sock, &request(&line, &[], &body)).await),
            403,
            "{body}"
        );
    }
}

#[tokio::test]
async fn only_allowlisted_betas_pass_and_the_content_type_is_the_gateways_own() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let resp = raw(
        &r.sock,
        &request(
            LINE,
            &[
                "Content-Type: text/plain",
                "anthropic-beta: claude-code-20250219, mcp-client-2025-04-04",
            ],
            &model_body(),
        ),
    )
    .await;
    assert_eq!(status(&resp), 200);
    let head = r.up.head(0).to_ascii_lowercase();
    assert!(
        head.contains("anthropic-beta: claude-code-20250219\r\n"),
        "{head}"
    );
    assert!(!head.contains("mcp-client"), "{head}");
    assert!(
        head.contains("content-type: application/json\r\n"),
        "{head}"
    );
    assert!(!head.contains("text/plain"), "{head}");
    // Only betas the list does not hold: the header is gone.
    let r = rig(Opts::anthropic(ok_script())).await;
    raw(
        &r.sock,
        &request(
            LINE,
            &["anthropic-beta: web-fetch-2025-09-10"],
            &model_body(),
        ),
    )
    .await;
    assert!(!r.up.head(0).to_ascii_lowercase().contains("anthropic-beta"));
}

#[tokio::test]
async fn a_request_holds_its_permit_before_its_body_is_read() {
    let mut o = Opts::anthropic(ok_script());
    o.grant.rate.concurrent = 1;
    let r = rig(o).await;
    // A client that promises a large body and sends little of it holds the one permit...
    let mut slow = UnixStream::connect(&r.sock).await.unwrap();
    slow.write_all(
        b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: 4000000\r\n\r\n{\"model\"",
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // ...so the next request is told so at once, whatever its body.
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 429, "{}", String::from_utf8_lossy(&resp));
    assert!(body_of(&resp).contains("gateway_busy"));
    assert_eq!(r.up.count(), 0);
}

#[tokio::test]
async fn reports_the_core_has_not_acknowledged_fail_closed() {
    let r = rig(Opts::anthropic(ok_script())).await;
    r.meter().set_unreported(true);
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 429);
    assert!(body_of(&resp).contains("gateway_unreported"));
    assert_eq!(r.up.count(), 0);
    r.meter().set_unreported(false);
    assert_eq!(
        status(&raw(&r.sock, &request(LINE, &[], &model_body())).await),
        200
    );
}

#[tokio::test]
async fn a_request_that_may_have_been_served_is_charged_its_estimate_never_nothing() {
    // The upstream read the request and then dropped the connection: a 502 to the harness, and
    // the hold (8 output tokens and the body's input) is spent, approximately.
    let mut r = rig(Opts::anthropic(vec![Step::Abrupt])).await;
    let resp = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&resp), 502);
    let rep = r.report().await;
    assert_eq!(rep.kind, GatewayReportKind::Usage);
    assert!(
        rep.approximate && rep.output == 8 && rep.input > 0,
        "{rep:?}"
    );
    assert!(r.no_report());
    assert!(r.meter().spent().0 > 8);
    // A refused address or a bad certificate never reached the upstream: nothing is spent.
    let mut o = Opts::anthropic(ok_script());
    o.answers = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))];
    let mut r = rig(o).await;
    raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(r.report().await.kind, GatewayReportKind::Upstream);
    assert_eq!(r.meter().spent(), (0, 0));
}

#[tokio::test]
async fn an_abort_while_the_upstream_is_still_thinking_is_charged_its_estimate() {
    // The upstream has the request and sends nothing: the gateway is dropped (a stop).
    let mut r = rig(Opts::anthropic(vec![Step::Wait(Arc::new(Notify::new()))])).await;
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    c.write_all(&request(LINE, &[], &model_body()))
        .await
        .unwrap();
    for _ in 0..250 {
        if r.up.count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(r.up.count(), 1, "the request reached the upstream");
    r.close();
    let rep = r.report().await;
    assert!(
        rep.approximate && rep.output == 8 && rep.input > 0,
        "{rep:?}"
    );
    assert!(r.no_report());
}

#[tokio::test]
async fn count_tokens_costs_nothing_and_reports_no_usage() {
    let body = r#"{"input_tokens":5}"#;
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    // A ceiling too small for any held request: a free one still goes.
    let mut r = rig(opts(vec![Step::Send(reply.into_bytes())], 1)).await;
    let resp = raw(
        &r.sock,
        &request(
            "POST /v1/messages/count_tokens HTTP/1.1",
            &[],
            &model_body(),
        ),
    )
    .await;
    assert_eq!(status(&resp), 200, "{}", String::from_utf8_lossy(&resp));
    assert!(r.no_report(), "count_tokens reported usage");
    assert_eq!(r.meter().spent(), (0, 0));
    // But the model and tool checks still apply to it.
    let resp = raw(
        &r.sock,
        &request(
            "POST /v1/messages/count_tokens HTTP/1.1",
            &[],
            r#"{"model":"unpriced"}"#,
        ),
    )
    .await;
    assert_eq!(status(&resp), 403);
}

#[tokio::test]
async fn a_reply_that_is_not_streamed_must_name_its_cap() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let bare = format!("{{\"model\":\"{MODEL}\"}}");
    let resp = raw(&r.sock, &request(LINE, &[], &bare)).await;
    assert_eq!(status(&resp), 400);
    assert!(body_of(&resp).contains("max_output_required"));
    assert_eq!(r.up.count(), 0);
    let streamed = format!("{{\"model\":\"{MODEL}\",\"stream\":true}}");
    assert_eq!(
        status(&raw(&r.sock, &request(LINE, &[], &streamed)).await),
        200
    );
}

#[tokio::test]
async fn more_candidates_background_runs_and_hidden_repeats_are_refused_over_the_wire() {
    let o = Opts::of(
        Wire::OpenaiResponses,
        "api.openai.com",
        "/v1",
        "openai",
        "sk-proj-",
        ok_script(),
    );
    let r = rig(o).await;
    let line = "POST /v1/responses HTTP/1.1";
    for body in [
        format!("{{\"model\":\"{MODEL}\",\"stream\":true,\"background\":true}}"),
        format!("{{\"model\":\"{MODEL}\",\"stream\":true,\"n\":4}}"),
    ] {
        let resp = raw(&r.sock, &request(line, &[], &body)).await;
        assert_eq!(status(&resp), 403, "{body}");
        assert!(body_of(&resp).contains("param_not_allowed"));
    }
    let hidden = format!(
        "{{\"model\":\"{MODEL}\",\"stream\":true,\"tools\":[{{\"type\":\"web_search\",\"type\":\"function\"}}]}}"
    );
    assert_eq!(
        status(&raw(&r.sock, &request(line, &[], &hidden)).await),
        400
    );
    assert_eq!(r.up.count(), 0);
}

#[tokio::test]
async fn an_upstream_that_refuses_the_key_ends_the_sessions_requests() {
    let reply = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}";
    let mut r = rig(Opts::anthropic(vec![Step::Send(reply.as_bytes().to_vec())])).await;
    let first = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&first), 401, "the refusal passes through");
    assert_eq!(r.report().await.status, UpstreamStatus::AuthFailed);
    let second = raw(&r.sock, &request(LINE, &[], &model_body())).await;
    assert_eq!(status(&second), 403);
    assert!(body_of(&second).contains("gateway_account_unusable"));
    assert_eq!(r.up.count(), 1, "no retry storm: the second never left");
}
