//! `ainkrad-runner __script <sock>` (E3.4): the process that runs one script. The shim spawns it
//! inside the sandbox, with a cleared environment; it reads one JSON request from stdin
//! (`{code, run, limits?}`), runs the engine with the socket client as its host, and writes ONE
//! JSON line to stdout (the [`Envelope`]). Nothing else is ever written to stdout (`console.log`
//! is captured by the engine), and a crash or abort of the engine ends only this process: the
//! shim sees a non-zero exit and says so.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::client::{Client, Refusal};
use super::engine::{self, ScriptError};
use super::{CALL, Limits, MAX_CODE, MAX_VALUE, cap};

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub code: String,
    /// Names this script's calls to the Core, which counts them per run.
    pub run: String,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub ok: bool,
    /// The final value as JSON text, already bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ScriptError>,
    pub logs: Vec<String>,
    pub calls: usize,
    pub ms: u64,
}

/// The longest one operation call waits (the relay's own bound is 120 s).
const CALL_WAIT: Duration = Duration::from_secs(125);

/// Runs `req` against the socket at `sock`; the engine's host is one [`Client`].
pub fn execute(sock: &str, req: &Request) -> Envelope {
    let started = Instant::now();
    let lim = req.limits.clamped();
    let end = started + lim.time();
    let done = |run: engine::Run| {
        let (ok, value, error) = match run.result {
            Ok(v) => (true, Some(cap(&v, MAX_VALUE)), None),
            Err(e) => (false, None, Some(e)),
        };
        Envelope {
            ok,
            value,
            error,
            logs: run.logs,
            calls: run.calls,
            ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    };
    if req.code.len() > MAX_CODE {
        return done(engine::Run {
            result: Err(ScriptError {
                message: format!("the script is over {MAX_CODE} bytes"),
                line: None,
                code: None,
            }),
            logs: vec![],
            calls: 0,
        });
    }
    let mut client: Option<Result<Client, Refusal>> = None;
    let sock = sock.to_owned();
    let run = req.run.clone();
    let host = move |op: &str, args: Value| {
        // Connected on the first call: a script that makes none never touches the socket.
        let c = client.get_or_insert_with(|| Client::connect(&sock));
        let c = c.as_mut().map_err(|r| r.clone())?;
        let wait = end.saturating_duration_since(Instant::now()).min(CALL_WAIT);
        c.call(
            CALL,
            &serde_json::json!({"op": op, "args": args, "run": run}),
            wait,
        )
    };
    done(engine::run(&req.code, &lim, host))
}

pub fn script_main(sock: &str) -> ExitCode {
    let mut input = Vec::new();
    // Bounded: the code, its JSON escaping and the framing.
    let cap = u64::try_from(MAX_CODE * 7).unwrap_or(u64::MAX);
    if std::io::stdin().take(cap).read_to_end(&mut input).is_err() {
        return ExitCode::FAILURE;
    }
    let Ok(req) = serde_json::from_slice::<Request>(&input) else {
        return ExitCode::FAILURE;
    };
    let envelope = execute(sock, &req);
    let Ok(mut line) = serde_json::to_vec(&envelope) else {
        return ExitCode::FAILURE;
    };
    line.push(b'\n');
    let mut out = std::io::stdout().lock();
    if out.write_all(&line).and_then(|()| out.flush()).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
