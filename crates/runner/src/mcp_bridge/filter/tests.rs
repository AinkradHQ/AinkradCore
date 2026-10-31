use super::*;
use tokio::io::BufReader;

const PATH: &str = "/token/citadel/v1/mcp";

async fn read(input: &[u8]) -> Result<Option<Request>, Refusal> {
    read_request(&mut BufReader::new(input), "core.example:8443", PATH).await
}

fn req(lines: &[&str]) -> Vec<u8> {
    format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes()
}

async fn refused(lines: &[&str]) -> u16 {
    read(&req(lines)).await.unwrap_err().0
}

#[tokio::test]
async fn the_one_route_is_rewritten_and_hop_headers_are_dropped() {
    let r = read(&req(&[
        "POST /token/citadel/v1/mcp HTTP/1.1",
        "hOsT: 127.0.0.1:47831",
        "Authorization: Bearer t",
        "Content-Length: 5",
        "Connection: keep-alive",
        "Keep-Alive: timeout=5",
        "TE: trailers",
    ]))
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r.body, Body::Length(5));
    assert_eq!(
        String::from_utf8(r.head).unwrap(),
        "POST /token/citadel/v1/mcp HTTP/1.1\r\nAuthorization: Bearer t\r\nContent-Length: 5\r\nHost: core.example:8443\r\n\r\n"
    );
}

#[tokio::test]
async fn other_paths_are_404_and_other_methods_403() {
    for target in [
        "/token/citadel/v1/mcp?x=1",
        "/token/citadel/v1/mcp/",
        "/token/citadel/v1/../v1/mcp",
        "/token/citadel/v1/%6dcp",
        "/token/citadel/v1/%2e%2e/mcp",
        "/handshake",
        "http://core.example:8443/token/citadel/v1/mcp",
        "*",
    ] {
        assert_eq!(
            refused(&[&format!("POST {target} HTTP/1.1")]).await,
            404,
            "{target}"
        );
    }
    for method in ["GET", "PUT", "DELETE", "OPTIONS", "post", "CONNECT"] {
        assert_eq!(
            refused(&[&format!("{method} {PATH} HTTP/1.1")]).await,
            403,
            "{method}"
        );
    }
    assert_eq!(refused(&["CONNECT core.example:443 HTTP/1.1"]).await, 403);
    assert_eq!(refused(&["POST /token/citadel/v1/mcp HTTP/1.0"]).await, 400);
}

#[tokio::test]
async fn upgrade_websocket_and_expect_are_refused() {
    let post = "POST /token/citadel/v1/mcp HTTP/1.1";
    assert_eq!(
        refused(&[post, "Upgrade: websocket", "Connection: Upgrade"]).await,
        403
    );
    assert_eq!(
        refused(&[post, "Connection: keep-alive, upgrade"]).await,
        403
    );
    assert_eq!(refused(&[post, "Upgrade: h2c"]).await, 403);
    assert_eq!(refused(&[post, "Expect: 100-continue"]).await, 403);
}

#[tokio::test]
async fn ambiguous_framing_is_refused() {
    let post = "POST /token/citadel/v1/mcp HTTP/1.1";
    for headers in [
        vec!["Content-Length: 5", "Content-Length: 5"],
        vec!["Content-Length: 5", "Content-Length: 6"],
        vec!["Content-Length: 5", "Transfer-Encoding: chunked"],
        vec!["Transfer-Encoding: chunked", "Transfer-Encoding: chunked"],
        vec!["Transfer-Encoding: xchunked"],
        vec!["Transfer-Encoding: gzip, chunked"],
        vec!["Content-Length: +5"],
        vec!["Content-Length: 5, 5"],
        vec!["Content-Length : 5"],
        vec!["Content-Length: 5", " Content-Length: 6"],
    ] {
        let mut lines = vec![post];
        lines.extend(headers.iter().copied());
        assert_eq!(refused(&lines).await, 400, "{headers:?}");
    }
    assert_eq!(refused(&[post, "Content-Length: 99999999"]).await, 413);
    // A bare line feed ends no header line.
    let bare = b"POST /token/citadel/v1/mcp HTTP/1.1\nHost: x\r\n\r\n";
    assert_eq!(read(bare).await.unwrap_err().0, 400);
}

#[tokio::test]
async fn heads_are_bounded_before_they_are_buffered() {
    // Endless bytes with no newline: the reader stops at the cap instead of growing.
    let endless = vec![b'A'; 10 * 1024 * 1024];
    assert_eq!(read(&endless).await.unwrap_err().0, 431);
    let long = format!(
        "POST /token/citadel/v1/mcp HTTP/1.1\r\nX: {}\r\n\r\n",
        "a".repeat(MAX_LINE)
    );
    assert_eq!(read(long.as_bytes()).await.unwrap_err().0, 431);
    let many: Vec<String> = (0..=MAX_HEADERS).map(|i| format!("X-{i}: v")).collect();
    let mut lines = vec!["POST /token/citadel/v1/mcp HTTP/1.1"];
    lines.extend(many.iter().map(String::as_str));
    assert_eq!(refused(&lines).await, 431);
    // Many medium lines pass the per-line cap but not the head cap.
    let wide: Vec<String> = (0..20)
        .map(|i| format!("X-{i}: {}", "a".repeat(2000)))
        .collect();
    let mut lines = vec!["POST /token/citadel/v1/mcp HTTP/1.1"];
    lines.extend(wide.iter().map(String::as_str));
    assert_eq!(refused(&lines).await, 431);
}

#[tokio::test(start_paused = true)]
async fn a_slow_head_times_out() {
    let (mut tx, rx) = tokio::io::duplex(64);
    tx.write_all(b"POST /token/citadel/v1/mcp HTTP/1.1\r\nX: a")
        .await
        .unwrap();
    // The rest never comes; paused time jumps past the head timeout.
    let got = read_request(&mut BufReader::new(rx), "h", PATH).await;
    assert_eq!(got.unwrap_err().0, 408);
}

#[tokio::test]
async fn bodies_are_bounded_and_chunked_ones_reframed() {
    let mut out = Vec::new();
    let mut r = BufReader::new(&b"3;ext\r\nabc\r\n0\r\n\r\n"[..]);
    assert!(
        forward_body(&mut r, &mut out, Body::Chunked).await.is_err(),
        "extensions are refused"
    );
    let mut r = BufReader::new(&b"3\r\nabc\r\n2\r\nde\r\n0\r\nTrailer: x\r\n\r\nNEXT"[..]);
    out.clear();
    forward_body(&mut r, &mut out, Body::Chunked).await.unwrap();
    assert_eq!(out, b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
    let mut rest = String::new();
    r.read_to_string(&mut rest).await.unwrap();
    assert_eq!(rest, "NEXT");
    for bad in [
        &b"ffffffffffffffff\r\n"[..],
        b"fffffff\r\n",
        b"-1\r\n",
        b"+5\r\n",
        b"3\r\nabcXX",
    ] {
        let mut r = BufReader::new(bad);
        assert!(
            forward_body(&mut r, &mut Vec::new(), Body::Chunked)
                .await
                .is_err(),
            "{bad:?}"
        );
    }
    let mut r = BufReader::new(&b"abc"[..]);
    assert!(
        forward_body(&mut r, &mut Vec::new(), Body::Length(5))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn keep_alive_requests_each_get_the_core_host() {
    let input = b"POST /token/citadel/v1/mcp HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhiPOST /token/citadel/v1/mcp HTTP/1.1\r\nHost: b\r\n\r\n";
    let mut r = BufReader::new(&input[..]);
    for _ in 0..2 {
        let q = read_request(&mut r, "core:1", PATH).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&q.head).contains("Host: core:1\r\n"));
        forward_body(&mut r, &mut Vec::new(), q.body).await.unwrap();
    }
    assert!(
        read_request(&mut r, "core:1", PATH)
            .await
            .unwrap()
            .is_none()
    );
}
