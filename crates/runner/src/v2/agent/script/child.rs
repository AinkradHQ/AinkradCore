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
    /// The calls that waited for a person, in order (E6.5).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<Approval>,
}

/// One call that waited for a person's approval, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub op: String,
    /// The approval's request id (`cm_…`).
    pub request: String,
    /// `approved`, `denied`, `timed_out`, or the refusal code of a call approved but not run.
    pub outcome: String,
}

impl Approval {
    fn of(op: &str, request: String, answer: &Result<Value, Refusal>) -> Self {
        let outcome = match answer {
            Ok(_) => "approved",
            Err(r) if r.code == "approval_denied" => "denied",
            Err(r) if r.code == "approval_timeout" => "timed_out",
            Err(r) => r.code.as_str(),
        };
        Self {
            op: op.to_owned(),
            request,
            outcome: outcome.to_owned(),
        }
    }
}

/// What the Core is told a call still waits, less than the script so its answer arrives in time.
const MARGIN: Duration = Duration::from_secs(1);

/// Runs `req` against the socket at `sock`; the engine's host is one [`Client`].
pub fn execute(sock: &str, req: &Request) -> Envelope {
    let started = Instant::now();
    let lim = req.limits.clamped();
    let end = started + lim.deadline();
    let approvals = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = approvals.clone();
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
            approvals: approvals.take(),
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
    let host = move |op: &str, args: Value, opts: Value| {
        // Connected on the first call: a script that makes none never touches the socket.
        let c = client.get_or_insert_with(|| Client::connect(&sock));
        let c = c.as_mut().map_err(|r| r.clone())?;
        // A call may wait as long as the script has left (a person's approval), never longer.
        let wait = end.saturating_duration_since(Instant::now());
        let wait_ms = u64::try_from(wait.saturating_sub(MARGIN).as_millis()).unwrap_or(u64::MAX);
        let mut body = serde_json::json!({"op": op, "args": args, "run": run, "wait_ms": wait_ms});
        if let (Value::Object(o), Some(b)) = (opts, body.as_object_mut()) {
            b.extend(o); // `key`, `repeat`: checked by the engine
        }
        let (answer, approval) = c.call_marked(CALL, &body, wait);
        if let Some(request) = approval {
            seen.borrow_mut().push(Approval::of(op, request, &answer));
        }
        answer
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
