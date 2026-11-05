//! The response half of a gateway request (KAN-435 G3/G4): the head the harness gets, the body
//! passed on piece by piece, and the cut when the ceiling is reached.
//!
//! The body's framing is the gateway's own: a length is passed on and checked, anything else is
//! chunked, and a stream that ends in an error, a cut or a stop never gets its last chunk, so the
//! harness sees an error and not a clean end.

use tokio::net::UnixStream;

use super::Config;
use super::charge::Charge;
use super::dial::{Body, Opened, Stream};
use super::serve::{End, put, reason};

/// How the body ended.
enum Pumped {
    Done,
    /// The upstream broke, stalled, or sent more than the response ceiling.
    Broken,
    /// The reply went past the ceiling: it is cut.
    Cut,
    ClientGone,
}

async fn pump(
    c: &mut UnixStream,
    body: &mut Body<Stream>,
    chunked: bool,
    charge: &mut Charge,
) -> Pumped {
    let mut sent = 0usize;
    loop {
        match body.next().await {
            Ok(Some(piece)) => {
                charge.feed(&piece);
                if charge.exceeded() {
                    return Pumped::Cut; // this piece is not passed on
                }
                sent += piece.len();
                let mut out = Vec::with_capacity(piece.len() + 16);
                if chunked {
                    out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                }
                out.extend_from_slice(&piece);
                if chunked {
                    out.extend_from_slice(b"\r\n");
                }
                if put(c, &out).await.is_err() {
                    return Pumped::ClientGone; // flushed per piece: a stream is not buffered here
                }
            }
            Ok(None) => {
                tracing::debug!(sent, "gateway response");
                return Pumped::Done;
            }
            Err(e) => {
                tracing::debug!(error = ?e, sent, "gateway response cut");
                return Pumped::Broken;
            }
        }
    }
}

/// Sends the response of `up` to the harness, charging `charge` for it.
pub(super) async fn respond(
    cfg: &Config,
    c: &mut UnixStream,
    mut up: Opened<Stream>,
    charge: &mut Charge,
) -> Result<(), End> {
    // The head: the allow-listed headers, minus any whose value holds the key.
    let key = cfg.key.expose();
    let mut head = format!("HTTP/1.1 {} {}\r\n", up.status, reason(up.status));
    for (n, v) in up.headers.iter().filter(|(_, v)| !v.contains(key)) {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    let framed = !matches!(up.status, 204 | 304);
    let chunked = framed && up.length.is_none();
    match up.length {
        Some(n) if framed => head.push_str(&format!("Content-Length: {n}\r\n")),
        _ if chunked => head.push_str("Transfer-Encoding: chunked\r\n"),
        _ => {}
    }
    head.push_str("Connection: close\r\n\r\n");
    put(c, head.as_bytes()).await?;
    // An `agent.limit` of zero aborts a stream that is idle on the upstream, too.
    let pumped = tokio::select! {
        p = pump(c, &mut up.body, chunked, charge) => p,
        () = cfg.meter.stopped() => Pumped::Cut,
    };
    match pumped {
        Pumped::Done => {
            charge.end(true);
            if chunked {
                put(c, b"0\r\n\r\n").await?;
            }
            Ok(())
        }
        Pumped::Broken | Pumped::Cut | Pumped::ClientGone => {
            charge.end(false);
            Err(End::Drop)
        }
    }
}
