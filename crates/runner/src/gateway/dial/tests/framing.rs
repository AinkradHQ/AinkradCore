//! Response head and body framing: what is refused whole, what is an error, what is reported.

use super::*;

async fn get(reply: &'static str, end: End, max: usize) -> Result<Reply, DialError> {
    let f = serve_as(HOST, reply, end).await;
    let (d, _) = dialer(&f, Script::of(vec![public()]), vec![]);
    d.request(HOST, "GET", "/x", &[], b"", max).await
}

#[tokio::test]
async fn a_head_with_a_bare_line_break_nul_or_a_bad_header_name_is_refused_whole() {
    for head in [
        // The injected `Location` rides on a bare LF inside what looks like one header.
        "HTTP/1.1 200 OK\r\nx-ratelimit-a\nLocation: http://x: y\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nx-ratelimit-a: 1\rLocation: http://x\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nx-ratelimit-a: 1\0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nx ratelimit: 1\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nx(a): 1\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\n: 1\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nno colon here\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nx-a: 1\r\n folded\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nx-a: \x07\r\nContent-Length: 0\r\n\r\n",
    ] {
        assert_eq!(
            get(head, End::Notify, 16).await,
            Err(DialError::Upstream),
            "{head:?}"
        );
    }
}

#[tokio::test]
async fn only_a_three_digit_status_from_100_to_599_is_a_status() {
    for line in [
        "HTTP/1.1 +20 OK",
        "HTTP/1.1 -20 OK",
        "HTTP/1.1 20 OK",
        "HTTP/1.1 2000 OK",
        "HTTP/1.1 099 X",
        "HTTP/1.1 600 X",
        "HTTP/1.1 2x0 X",
        "HTTP/1.0 200 OK",
        "HTTP/1.1  200 OK",
    ] {
        let reply = Box::leak(format!("{line}\r\nContent-Length: 0\r\n\r\n").into_boxed_str());
        assert_eq!(
            get(reply, End::Notify, 16).await,
            Err(DialError::Upstream),
            "{line}"
        );
    }
    let ok = get("HTTP/1.1 599\r\nContent-Length: 0\r\n\r\n", End::Notify, 16)
        .await
        .unwrap();
    assert_eq!(ok.status, 599);
}

#[tokio::test]
async fn interim_responses_are_skipped_and_a_switch_is_refused() {
    let done = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early\r\nLink: x\r\n\r\n\
        HTTP/1.1 200 OK\r\ncontent-type: a/b\r\nContent-Length: 2\r\n\r\nhi";
    let reply = get(done, End::Notify, 16).await.unwrap();
    assert_eq!((reply.status, reply.body.as_slice()), (200, &b"hi"[..]));
    assert_eq!(
        reply.headers,
        [("content-type".to_owned(), "a/b".to_owned())]
    );
    let switch = "HTTP/1.1 101 Switching\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(get(switch, End::Notify, 16).await, Err(DialError::Upstream));
}

#[tokio::test]
async fn a_cut_stream_is_an_error_never_a_clean_end() {
    // Content-Length promises 10, the TLS stream ends without close_notify after 3.
    let cut = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
    assert_eq!(get(cut, End::Abrupt, 64).await, Err(DialError::Upstream));
    // Close-delimited: without close_notify the body's end cannot be trusted either.
    let open = "HTTP/1.1 200 OK\r\n\r\nabc";
    assert_eq!(get(open, End::Abrupt, 64).await, Err(DialError::Upstream));
    assert_eq!(get(open, End::Notify, 64).await.unwrap().body, b"abc");
    // Cut in the head, and cut inside a chunk.
    assert_eq!(
        get("HTTP/1.1 200 OK\r\nx-a: 1", End::Notify, 64).await,
        Err(DialError::Upstream)
    );
    let chunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab";
    assert_eq!(get(chunk, End::Abrupt, 64).await, Err(DialError::Upstream));
    assert_eq!(get(chunk, End::Notify, 64).await, Err(DialError::Upstream));
}

#[tokio::test]
async fn content_length_is_honoured_and_a_short_body_is_an_error() {
    let ok = get(
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        End::Notify,
        64,
    )
    .await
    .unwrap();
    assert_eq!(
        (ok.body.as_slice(), ok.truncated, ok.chunked),
        (&b"abc"[..], false, false)
    );
    // Bytes past the length are not part of the body.
    let extra = get(
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef",
        End::Notify,
        64,
    )
    .await
    .unwrap();
    assert_eq!(
        (extra.body.as_slice(), extra.truncated),
        (&b"abc"[..], false)
    );
    // Short with a clean close: still an error.
    let short = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
    assert_eq!(get(short, End::Notify, 64).await, Err(DialError::Upstream));
    // Exactly the cap is not truncated; one more is.
    let at = get(
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd",
        End::Notify,
        4,
    )
    .await
    .unwrap();
    assert_eq!((at.body.as_slice(), at.truncated), (&b"abcd"[..], false));
    let over = get(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde",
        End::Notify,
        4,
    )
    .await
    .unwrap();
    assert_eq!((over.body.as_slice(), over.truncated), (&b"abcd"[..], true));
    // Refused framings: duplicates, non-digits, a sign, and Content-Length with Transfer-Encoding.
    for head in [
        "Content-Length: 1\r\nContent-Length: 1",
        "Content-Length: 1\r\nContent-Length: 2",
        "Content-Length: +1",
        "Content-Length: 0x1",
        "Content-Length: 1, 1",
        "Content-Length: ",
        "Content-Length: 99999999999999999999",
        "Content-Length: 1\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: gzip",
        "Transfer-Encoding: gzip, chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
    ] {
        let reply = Box::leak(format!("HTTP/1.1 200 OK\r\n{head}\r\n\r\nabcdef").into_boxed_str());
        assert_eq!(
            get(reply, End::Notify, 64).await,
            Err(DialError::Upstream),
            "{head}"
        );
    }
}

#[tokio::test]
async fn a_chunked_body_is_decoded_and_reported_as_chunked() {
    let body = "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n3\r\nabc\r\n4;ext=1\r\ndefg\r\n0\r\nX-T: 1\r\n\r\n";
    let reply = get(body, End::Notify, 64).await.unwrap();
    assert_eq!(
        (reply.body.as_slice(), reply.chunked, reply.truncated),
        (&b"abcdefg"[..], true, false)
    );
    // Truncation at the cap, inside a chunk and between chunks, is explicit.
    let cut = get(body, End::Notify, 5).await.unwrap();
    assert_eq!((cut.body.as_slice(), cut.truncated), (&b"abcde"[..], true));
    let between = get(body, End::Notify, 3).await.unwrap();
    assert_eq!(
        (between.body.as_slice(), between.truncated),
        (&b"abc"[..], true)
    );
    let exact = get(body, End::Notify, 7).await.unwrap();
    assert_eq!(
        (exact.body.as_slice(), exact.truncated),
        (&b"abcdefg"[..], false)
    );
    // Malformed: a bad size, a missing CRLF after data, no last chunk, endless trailers.
    for chunks in [
        "zz\r\nab\r\n0\r\n\r\n",
        "2\r\nabXX0\r\n\r\n",
        "2\r\nab\r\n",
        "\r\n",
        "-1\r\n",
        "2\r\nab\r\n0\r\nX: 1\r\n",
    ] {
        let reply = Box::leak(
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}")
                .into_boxed_str(),
        );
        assert_eq!(
            get(reply, End::Notify, 64).await,
            Err(DialError::Upstream),
            "{chunks:?}"
        );
    }
}

#[tokio::test]
async fn a_close_delimited_body_reports_truncation_at_the_cap() {
    let at = get("HTTP/1.1 200 OK\r\n\r\nabcd", End::Notify, 4)
        .await
        .unwrap();
    assert_eq!((at.body.as_slice(), at.truncated), (&b"abcd"[..], false));
    let over = get("HTTP/1.1 200 OK\r\n\r\nabcde", End::Notify, 4)
        .await
        .unwrap();
    assert_eq!((over.body.as_slice(), over.truncated), (&b"abcd"[..], true));
    // No body status never reads one.
    let none = get("HTTP/1.1 204 No Content\r\n\r\nignored", End::Notify, 4)
        .await
        .unwrap();
    assert_eq!(
        (none.status, none.body.as_slice(), none.truncated),
        (204, &b""[..], false)
    );
}

#[tokio::test]
async fn one_total_duration_cap_covers_a_response_that_trickles_or_stalls() {
    let f = serve_as(
        HOST,
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab",
        End::Stall,
    )
    .await;
    let (d, _) = dialer(&f, Script::of(vec![public()]), vec![]);
    let d = d.with_total(Duration::from_millis(300));
    let started = std::time::Instant::now();
    assert_eq!(
        d.request(HOST, "GET", "/x", &[], b"", 64).await,
        Err(DialError::Upstream)
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}
