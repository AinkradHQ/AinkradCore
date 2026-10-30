//! The reference terminal client: REST lifecycle plus a resumable raw-mode WebSocket attach.

use std::io::Write;
use std::process::Command;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

use crate::Error;
use crate::client::{Client, parse};
use crate::devices::s;

const WINDOW: u64 = 64 * 1024;

fn line(out: &mut impl Write, value: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{value}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

fn id(id: &str) -> Result<&str, Error> {
    let ok = id.strip_prefix("t_").is_some_and(|b| {
        (1..=40).contains(&b.len())
            && b.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    });
    ok.then_some(id)
        .ok_or_else(|| Error::Usage(format!("{id:?} is not a terminal id (t_…)")))
}

fn size(rows: Option<i64>, cols: Option<i64>) -> Result<(u16, u16), Error> {
    let (mut r, mut c) = (rows.unwrap_or(24), cols.unwrap_or(80));
    if (rows.is_none() || cols.is_none())
        && let Ok(out) = Command::new("stty").arg("size").output()
    {
        let words: Vec<_> = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(str::parse::<i64>)
            .collect::<Result<_, _>>()
            .unwrap_or_default();
        if rows.is_none() {
            r = words.first().copied().unwrap_or(r);
        }
        if cols.is_none() {
            c = words.get(1).copied().unwrap_or(c);
        }
    }
    if (1..=1000).contains(&r) && (1..=1000).contains(&c) {
        Ok((r as u16, c as u16))
    } else {
        Err(Error::Usage("rows and cols must be 1..1000".into()))
    }
}

fn tty_size() -> Option<(u16, u16)> {
    let out = Command::new("stty").arg("size").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut words = text.split_whitespace().map(str::parse::<u16>);
    let rows = words.next()?.ok()?;
    let cols = words.next()?.ok()?;
    (1..=1000).contains(&rows).then_some(())?;
    (1..=1000).contains(&cols).then_some(())?;
    Some((rows, cols))
}

fn frame(kind: &str, payload: Value, seq: u64) -> Value {
    json!({"stream_id": 0, "kind": kind, "seq": seq, "payload": payload})
}

async fn send(ws: &mut crate::net::Ws, value: Value) -> Result<(), Error> {
    ws.send(Message::Text(value.to_string().into()))
        .await
        .map_err(|e| Error::Unreachable(format!("terminal socket: {e}")))
}

fn output_data(payload: &Value) -> Option<Vec<u8>> {
    payload
        .get("data")
        .and_then(Value::as_str)
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
}

struct RawMode(Option<String>);
impl RawMode {
    fn enter() -> Result<Self, Error> {
        let saved = Command::new("stty")
            .arg("-g")
            .output()
            .map_err(|e| Error::Unreachable(format!("stty: {e}")))?;
        let saved = String::from_utf8_lossy(&saved.stdout).trim().to_owned();
        let status = Command::new("stty")
            .args(["-icanon", "-echo", "min", "1", "time", "0"])
            .status()
            .map_err(|e| Error::Unreachable(format!("stty: {e}")))?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| Error::Usage("attach requires a terminal on stdin".into()))?;
        Ok(Self(Some(saved)))
    }
}
impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(saved) = self.0.take() {
            let _ = Command::new("stty").arg(saved).status();
        }
    }
}

async fn attach_once(c: &mut Client, terminal: &str, after: u64) -> Result<(bool, u64), Error> {
    let mut ws = c
        .websocket(
            &format!("/api/v1/terminals/{terminal}/ws"),
            &format!("after={after}"),
        )
        .await?;
    send(&mut ws, frame("credit", json!({"bytes": WINDOW}), 0)).await?;
    let mut input = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 4096];
    let mut wire_seq = 1;
    let mut next = after;
    let mut last_size = tty_size();
    let mut resize_tick = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            _ = resize_tick.tick() => {
                if let Some((rows, cols)) = tty_size() && last_size != Some((rows, cols)) {
                    send(&mut ws, frame("control", json!({"type":"resize","rows":rows,"cols":cols}), wire_seq)).await?;
                    wire_seq += 1;
                    last_size = Some((rows, cols));
                }
            }
            read = input.read(&mut buf) => {
                let n = read.map_err(|e| Error::Unreachable(format!("stdin: {e}")))?;
                if n == 0 { return Ok((false, next)); }
                if let Some(pos) = buf[..n].iter().position(|b| *b == 0x1c) {
                    if pos > 0 { send(&mut ws, frame("output", json!({"data": base64::engine::general_purpose::STANDARD.encode(&buf[..pos])}), wire_seq)).await?; }
                    let _ = ws.close(None).await;
                    return Ok((false, next));
                }
                send(&mut ws, frame("output", json!({"data": base64::engine::general_purpose::STANDARD.encode(&buf[..n])}), wire_seq)).await?;
                wire_seq += 1;
            }
            incoming = ws.next() => {
                let Some(Ok(message)) = incoming else { return Ok((true, next)); };
                let bytes = match message {
                    Message::Text(text) => text.as_bytes().to_vec(),
                    Message::Binary(bytes) => bytes.to_vec(),
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(_) => return Ok((true, next)),
                    _ => continue,
                };
                let f: Value = serde_json::from_slice(&bytes).map_err(|e| Error::Protocol(format!("terminal frame: {e}")))?;
                match f["kind"].as_str().unwrap_or("") {
                    "control" => match f["payload"]["type"].as_str().unwrap_or("") {
                        "opened" => { next = f["payload"]["seq"].as_u64().unwrap_or(next); }
                        "snapshot" => { let data = output_data(&f["payload"]).unwrap_or_default(); stdout.write_all(&data).await.map_err(|e| Error::Unreachable(format!("stdout: {e}")))?; stdout.flush().await.ok(); next = f["payload"]["seq"].as_u64().unwrap_or(next); send(&mut ws, frame("credit", json!({"bytes": data.len()}), wire_seq)).await?; wire_seq += 1; }
                        _ => {}
                    },
                    "output" => { let data = output_data(&f["payload"]).unwrap_or_default(); stdout.write_all(&data).await.map_err(|e| Error::Unreachable(format!("stdout: {e}")))?; stdout.flush().await.ok(); next = next.checked_add(data.len() as u64).ok_or_else(|| Error::Protocol("terminal sequence overflow".into()))?; send(&mut ws, frame("credit", json!({"bytes": data.len()}), wire_seq)).await?; wire_seq += 1; }
                    "result" => return Ok((false, next)),
                    _ => {}
                }
            }
        }
    }
}

async fn attach(c: &mut Client, terminal: &str) -> Result<(), Error> {
    let _raw = RawMode::enter()?;
    let mut after = 0;
    loop {
        match attach_once(c, terminal, after).await {
            Ok((done, seq)) if done => {
                after = seq;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(_) => return Ok(()),
            Err(Error::Unreachable(_)) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

pub struct Options<'a> {
    pub rows: Option<i64>,
    pub cols: Option<i64>,
    pub cwd: Option<&'a str>,
    pub signal: Option<&'a str>,
}

pub async fn terminal(
    c: &mut Client,
    words: &[&str],
    options: &Options<'_>,
    json_out: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => { let v: Value = c.get("/api/v1/terminals", "").await?; if json_out { line(out, v) } else { for t in v.as_array().into_iter().flatten() { line(out, format_args!("{}\t{}\t{}\tseq {}", s(&t["id"]), s(&t["status"]), s(&t["runner"]), t["seq"]))?; } Ok(()) } }
        ["new", runner, rest @ ..] => {
            let (r, co) = size(options.rows, options.cols)?;
            let mut body = json!({"runner": runner, "size": {"rows": r, "cols": co}});
            if let Some(p) = rest.first() {
                body["program"] = json!(p);
                body["args"] = json!(&rest[1..]);
            };
            if let Some(d) = options.cwd {
                body["cwd"] = json!(d);
            }
            let res = c.call("POST", "/api/v1/terminals", "", Some(&body)).await?;
            let v: Value = parse(&res)?;
            if json_out { line(out, v) } else { line(out, s(&v["id"])) }
        }
        ["attach", terminal] => attach(c, id(terminal)?).await,
        ["detach", terminal] => { let _ = c.websocket(&format!("/api/v1/terminals/{}/ws", id(terminal)?), "after=0").await?; Ok(()) }
        ["resize", terminal] => { let (r, co) = size(options.rows, options.cols)?; let mut ws = c.websocket(&format!("/api/v1/terminals/{}/ws", id(terminal)?), "after=0").await?; send(&mut ws, frame("control", json!({"type":"resize","rows":r,"cols":co}), 0)).await?; ws.close(None).await.ok(); Ok(()) }
        ["signal", terminal] => { let sig = options.signal.ok_or_else(|| Error::Usage("term signal <id> --signal <name>".into()))?; let body = json!({"signal": sig}); let _ = c.call("POST", &format!("/api/v1/terminals/{}/signal", id(terminal)?), "", Some(&body)).await?; Ok(()) }
        ["close" | "kill", terminal] => { let res = c.call("DELETE", &format!("/api/v1/terminals/{}", id(terminal)?), "", None).await?; if json_out { line(out, parse::<Value>(&res)?) } else { line(out, "closed") } }
        _ => Err(Error::Usage("term new <runner> [program args…] | ls | attach <id> | detach <id> | resize <id> | signal <id> --signal <name> | close <id>".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_are_boundary_checked() {
        assert!(id("t_a").is_ok());
        assert!(id("x").is_err());
        assert!(id("t_../x").is_err());
    }
    #[test]
    fn sizes_are_bounded() {
        assert!(size(Some(0), Some(80)).is_err());
        assert_eq!(size(Some(24), Some(80)).unwrap(), (24, 80));
    }
}
