//! `events tail`: replay over HTTP from a seq, then follow the WebSocket, resuming with
//! `Last-Event-ID` set to the last seq printed after any drop or Core restart. Prints one JSON
//! event per line, each seq once and in order. Past the retention floor (HTTP 410 or close
//! 4410) it stops with `Error::PastRetention`; a revocation (close 4001) with `Error::Revoked`.

use std::io::Write;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;

use crate::Error;
use crate::client::{Client, parse, refusal};
use crate::net::WsError;

const PAGE: u32 = 1000;

#[derive(Deserialize)]
struct Page {
    items: Vec<Value>,
    next_after: Option<i64>,
}

fn emit(out: &mut impl Write, last: &mut i64, event: &Value) -> Result<(), Error> {
    let Some(seq) = event["seq"].as_i64() else {
        return Err(Error::Protocol("an event without a seq".into()));
    };
    // A resume may repeat what was already printed; never print a seq twice.
    if seq > *last {
        writeln!(out, "{event}")
            .and_then(|()| out.flush())
            .map_err(|e| Error::Unreachable(format!("stdout: {e}")))?;
        *last = seq;
    }
    Ok(())
}

/// The newest seq (`GET /api/v1/events/latest`).
pub async fn latest(client: &mut Client) -> Result<i64, Error> {
    let v: Value = client.get("/api/v1/events/latest", "").await?;
    v["seq"]
        .as_i64()
        .ok_or_else(|| Error::Protocol("events/latest without a seq".into()))
}

/// Prints every event after `after` (default: from now on); with `follow`, keeps going.
pub async fn tail(
    client: &mut Client,
    after: Option<i64>,
    follow: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let mut last = match after {
        Some(a) => a,
        None => latest(client).await?,
    };
    loop {
        let res = client
            .call(
                "GET",
                "/api/v1/events",
                &format!("after={last}&limit={PAGE}"),
                None,
            )
            .await?;
        let page: Page = parse(&res)?;
        for e in &page.items {
            emit(out, &mut last, e)?;
        }
        if page.next_after.is_none() {
            break;
        }
    }
    if !follow {
        return Ok(());
    }
    let mut backoff = Duration::from_millis(250);
    loop {
        match follow_once(client, &mut last, out).await {
            // A clean end (the Core restarting, a dropped connection): resume.
            Ok(()) => backoff = Duration::from_millis(250),
            Err(e @ (Error::Unreachable(_) | Error::Protocol(_))) => {
                eprintln!("events: {e}; resuming after {last}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
            Err(e) => return Err(e),
        }
    }
}

/// One WebSocket, from `last`, until it closes. Close 4001 and 4410 end the tail.
async fn follow_once(
    client: &mut Client,
    last: &mut i64,
    out: &mut impl Write,
) -> Result<(), Error> {
    let path = "/api/v1/events/ws";
    let mut ws = None;
    for retry in [false, true] {
        let s = client.session().await?;
        let mut headers = client.sign("GET", path, "", Some(&s.id), &[]);
        headers.push(("last-event-id", last.to_string()));
        match client.net.websocket(path, &headers).await {
            Ok(socket) => {
                ws = Some(socket);
                break;
            }
            Err(WsError::Refused(res)) => match refusal(&res, client.now()) {
                // The session died with a restart: renew and try once more.
                Error::Refused { code, .. } if code == "session_expired" && !retry => {
                    client.drop_session()
                }
                e => return Err(e),
            },
            Err(WsError::Net(e)) => {
                // The Core may be restarting: its next answer needs a new session anyway.
                client.drop_session();
                return Err(e);
            }
        }
    }
    let mut ws = ws.ok_or_else(|| Error::Protocol("the upgrade was refused twice".into()))?;
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(t)) => {
                let event: Value = serde_json::from_str(&t)
                    .map_err(|_| Error::Protocol("an event frame that is not JSON".into()))?;
                emit(out, last, &event)?;
            }
            Ok(Message::Ping(p)) => {
                let _ = ws.send(Message::Pong(p)).await;
            }
            Ok(Message::Close(frame)) => {
                let (code, reason) = frame.map_or((0, String::new()), |f| {
                    (u16::from(f.code), f.reason.to_string())
                });
                return match code {
                    4001 => Err(Error::Revoked),
                    4410 => Err(Error::PastRetention {
                        floor: floor_of(&reason).ok_or_else(|| {
                            Error::Protocol(format!("4410 without a floor: {reason}"))
                        })?,
                    }),
                    // 4003 scope_changed, 1012 restarting, 1013 too slow, 1001 no pong:
                    // reconnect from the last seq printed.
                    _ => {
                        client.drop_session();
                        Ok(())
                    }
                };
            }
            Ok(_) => {}
            Err(e) => {
                client.drop_session();
                return Err(Error::Unreachable(format!("event stream: {e}")));
            }
        }
    }
    Ok(())
}

/// `past retention, floor <seq>; …` → the seq.
fn floor_of(reason: &str) -> Option<i64> {
    let rest = reason.split("floor ").nth(1)?;
    rest.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_and_dedup() {
        assert_eq!(
            floor_of("past retention, floor 42; re-sync from /api/v1/events/latest"),
            Some(42)
        );
        assert_eq!(floor_of("revoked"), None);
        let (mut out, mut last) = (Vec::new(), 1);
        for seq in [1, 2, 2, 3] {
            emit(&mut out, &mut last, &serde_json::json!({"seq": seq})).unwrap();
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"seq\":2}\n{\"seq\":3}\n"
        );
    }
}
