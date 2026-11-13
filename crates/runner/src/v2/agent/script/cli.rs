//! The `ainkrad` CLI (E3.5): the same operations as `ainkrad_run`, for a shell. JSON in (`--json`
//! text, or `--json -` for stdin), JSON out. It is the runner executable run as `ainkrad-runner
//! ainkrad ...` (or under the name `ainkrad`), and it authenticates the way a script does: by the
//! session's socket, whose path is in `AINKRAD_TOOLS_SOCK` (never an argument, never a token).
//!
//! ```text
//! ainkrad search <words...>            ainkrad schema [op]
//! ainkrad <group> <op> [--json '{..}' | --json -] [--key K]
//! ```
//! Exit codes: 0 ok, 1 the CLI or socket failed, 2 refused, 3 approval denied or timed out,
//! 4 a limit (rate, size, call count, time). A refusal is `{"error":{"code","message"}}` on stderr.

use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

use serde_json::{Value, json};

use super::client::{Client, Refusal};
use super::{CALL, MAX_CALL_ARGS, SCHEMA, SEARCH, SOCK_ENV};

const WAIT: Duration = Duration::from_secs(125);

/// The exit code for a refusal code.
pub fn exit_for(code: &str) -> u8 {
    match code {
        "unavailable" | "protocol" => 1,
        "approval_denied" | "approval_timeout" => 3,
        "rate_limited" | "too_many_calls" | "args_too_large" | "busy" | "too_large" | "timeout"
        | "run_timeout" | "limit" => 4,
        _ => 2,
    }
}

fn fail(code: &str, message: &str) -> (u8, String, String) {
    let e = json!({"error": {"code": code, "message": message}});
    (exit_for(code), String::new(), format!("{e}\n"))
}

/// Runs one command line; returns the exit code, stdout and stderr text.
pub fn exec(args: &[&str], sock: Option<&str>, stdin: &mut dyn Read) -> (u8, String, String) {
    let (mut words, mut json_arg, mut key) = (Vec::new(), None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--json" => json_arg = it.next().map(|s| (*s).to_owned()),
            "--key" => key = it.next().map(|s| (*s).to_owned()),
            w => words.push(w),
        }
    }
    let (tool, body) = match words.as_slice() {
        ["search", q @ ..] if !q.is_empty() => (SEARCH, json!({"query": q.join(" ")})),
        ["schema"] => (SCHEMA, json!({})),
        ["schema", op] => (SCHEMA, json!({"op": op})),
        [_group, op] => {
            let text = match json_arg.as_deref() {
                None => "{}".to_owned(),
                Some("-") => {
                    let mut s = String::new();
                    let mut cap = stdin.take(MAX_CALL_ARGS as u64 + 1);
                    if cap.read_to_string(&mut s).is_err() || s.len() > MAX_CALL_ARGS {
                        return fail("args_too_large", "stdin is not text or is too large");
                    }
                    s
                }
                Some(t) => t.to_owned(),
            };
            let Ok(a @ Value::Object(_)) = serde_json::from_str::<Value>(&text) else {
                return fail("bad_args", "--json is a JSON object");
            };
            let mut b = json!({"op": op, "args": a});
            if let Some(k) = key {
                b["key"] = json!(k);
            }
            (CALL, b)
        }
        _ => {
            return (
                1,
                String::new(),
                "usage: ainkrad search <words> | ainkrad schema [op] | ainkrad <group> <op> [--json '{..}'|-] [--key K]\n"
                    .to_owned(),
            );
        }
    };
    let Some(sock) = sock.filter(|s| !s.is_empty()) else {
        return fail(
            "unavailable",
            &format!("{SOCK_ENV} is not set: no session socket"),
        );
    };
    match Client::connect(sock).and_then(|mut c| c.call(tool, &body, WAIT)) {
        Ok(v) => (0, format!("{v}\n"), String::new()),
        Err(Refusal { code, message }) => fail(&code, &message),
    }
}

pub fn main(args: &[&str]) -> ExitCode {
    let sock = std::env::var(SOCK_ENV).ok();
    let (code, out, err) = exec(args, sock.as_deref(), &mut std::io::stdin());
    print!("{out}");
    eprint!("{err}");
    ExitCode::from(code)
}
