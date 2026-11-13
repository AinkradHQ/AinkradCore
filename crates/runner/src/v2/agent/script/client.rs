//! The socket client shared by the script child and the CLI (E3.3): one connection to the session's
//! `tools.sock`, one blocking request at a time, the relay's own limits kept (`sock.rs`). A refusal
//! is returned as data ([`Refusal`]), never a panic: the Core's `{code, message}`, or one of ours
//! (`unavailable`, `args_too_large`, `timeout`, `protocol`).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use ainkrad_proto::v2::{MAX_ARGS_BYTES, MAX_RESULT_BYTES};
use serde_json::{Value, json};

use super::super::tools::sock::MAX_REQUEST;

/// The longest reply line read: a result at its cap, JSON-escaped inside the MCP text, plus framing.
const MAX_REPLY: usize = 3 * MAX_RESULT_BYTES + 4096;
/// Notification lines skipped while waiting for an answer.
const MAX_NOISE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: String,
    pub message: String,
}

impl Refusal {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }
}

pub struct Client {
    read: BufReader<UnixStream>,
    write: UnixStream,
    next: u64,
}

impl Client {
    pub fn connect(path: &str) -> Result<Self, Refusal> {
        let un = |e: std::io::Error| Refusal::new("unavailable", &format!("tools socket: {e}"));
        let stream = UnixStream::connect(path).map_err(un)?;
        let write = stream.try_clone().map_err(un)?;
        Ok(Self {
            read: BufReader::new(stream),
            write,
            next: 1,
        })
    }

    /// Calls the tool `name` (MCP spelling, `ainkrad_call`) and waits at most `wait` for the answer:
    /// the Core's result, or its refusal.
    pub fn call(&mut self, name: &str, args: &Value, wait: Duration) -> Result<Value, Refusal> {
        self.call_marked(name, args, wait).0
    }

    /// [`Client::call`], with the request id of the person's approval the call waited for, if any.
    pub fn call_marked(
        &mut self,
        name: &str,
        args: &Value,
        wait: Duration,
    ) -> (Result<Value, Refusal>, Option<String>) {
        match self.exchange(name, args, wait) {
            Ok(v) => {
                let approval = v["result"]["_meta"]["approval"].as_str().map(str::to_owned);
                (unwrap(&v), approval)
            }
            Err(r) => (Err(r), None),
        }
    }

    /// Sends one call and reads its answer line.
    fn exchange(&mut self, name: &str, args: &Value, wait: Duration) -> Result<Value, Refusal> {
        let unavailable =
            |e: std::io::Error| Refusal::new("unavailable", &format!("tools socket: {e}"));
        if args.to_string().len() > MAX_ARGS_BYTES {
            return Err(Refusal::new(
                "args_too_large",
                "the arguments are too large",
            ));
        }
        let id = self.next;
        self.next += 1;
        let mut line = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": name, "arguments": args}})
        .to_string();
        if line.len() >= MAX_REQUEST {
            return Err(Refusal::new("args_too_large", "the request is too large"));
        }
        line.push('\n');
        self.write
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(unavailable)?;
        self.write.write_all(line.as_bytes()).map_err(unavailable)?;
        self.read
            .get_ref()
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .map_err(unavailable)?;
        for _ in 0..MAX_NOISE {
            let mut buf = Vec::new();
            let n = (&mut self.read)
                .take(u64::try_from(MAX_REPLY).unwrap_or(u64::MAX) + 1)
                .read_until(b'\n', &mut buf);
            match n {
                Ok(0) => return Err(Refusal::new("unavailable", "the tools socket closed")),
                Ok(_) if buf.len() > MAX_REPLY => {
                    return Err(Refusal::new("protocol", "the reply is too large"));
                }
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(Refusal::new("timeout", "no answer in time"));
                }
                Err(e) => return Err(unavailable(e)),
            }
            let Ok(v) = serde_json::from_slice::<Value>(&buf) else {
                return Err(Refusal::new("protocol", "the reply is not JSON"));
            };
            if v["id"] != json!(id) {
                continue; // a notification, or the answer of a call we no longer wait for
            }
            return Ok(v);
        }
        Err(Refusal::new("protocol", "no answer among the messages"))
    }
}

/// The Core's answer inside the MCP envelope.
fn unwrap(v: &Value) -> Result<Value, Refusal> {
    if let Some(e) = v.get("error") {
        return Err(Refusal::new(
            "protocol",
            e["message"].as_str().unwrap_or("error"),
        ));
    }
    let r = &v["result"];
    let text = r["content"][0]["text"].as_str().unwrap_or("null");
    let body: Value = serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()));
    if r["isError"] == true {
        let s = |k: &str, d: &str| body[k].as_str().unwrap_or(d).to_owned();
        return Err(Refusal {
            code: s("code", "refused"),
            message: s("message", "the Core refused the call"),
        });
    }
    Ok(body)
}
