//! The script engine (E3.2): QuickJS with no ambient authority. The only globals are
//! `ainkrad.<group>.<op>(args)` (synchronous from the script's view) and `console`; there is no
//! `require`, `fetch`, `process`, timer, module loader, `std`/`os` or `WebAssembly`, and `import()`
//! and `import.meta` are refused. `Eval`, `Json`, `Promise` and `Proxy` are the intrinsics created:
//! without `Json` the bridge cannot work, and without `Promise` a script that calls `import('x')`
//! makes QuickJS `abort()` the process (E3.1 finding), so it is there to refuse it plainly.
//!
//! Budgets: wall time (an interrupt handler), memory (`set_memory_limit`), stack, the number of
//! operation calls and the size of one call's arguments. A refused call or a budget hit reaches the
//! script as a thrown `Error` with a `code` it may catch.
//!
//! The group of `ainkrad.<group>.<op>` is for the model's reading; the wire names the op alone
//! (ponytail: a wrong group still runs the op; the Core's catalogue is the authority).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Instant;

use rquickjs::{Context, Ctx, Function, Runtime, context::intrinsic};
use serde_json::Value;

use super::client::Refusal;
use super::{Limits, MAX_CALL_ARGS, MAX_CONSOLE};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScriptError {
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl ScriptError {
    fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            line: None,
            code: None,
        }
    }
}

pub struct Run {
    /// The final value as JSON text.
    pub result: Result<String, ScriptError>,
    pub logs: Vec<String>,
    /// Operation calls made (refused ones included).
    pub calls: usize,
}

const PRELUDE: &str = r#"(function (op, log) {
  const call = (name, args) => {
    const r = JSON.parse(op(name, JSON.stringify(args === undefined ? {} : args)));
    if (r.err) { const e = new Error(r.err.message); e.code = r.err.code; throw e; }
    return r.ok;
  };
  const ro = () => { throw new TypeError('ainkrad is read-only'); };
  const named = (n) => typeof n === 'string' && n !== 'then' && n !== 'toJSON';
  const group = () => new Proxy({}, { get: (_, n) => named(n) ? (a) => call(n, a) : undefined, set: ro, defineProperty: ro, deleteProperty: ro });
  globalThis.ainkrad = new Proxy({}, { get: (_, g) => named(g) ? group() : undefined, set: ro, defineProperty: ro, deleteProperty: ro });
  const show = (x) => { if (typeof x === 'string') return x; try { const s = JSON.stringify(x); return s === undefined ? String(x) : s; } catch (e) { return String(x); } };
  const say = (...a) => log(a.map(show).join(' '));
  globalThis.console = Object.freeze({ log: say, info: say, warn: say, error: say });
})(__op, __log); delete globalThis.__op; delete globalThis.__log;"#;

fn describe(ctx: &Ctx<'_>, e: &rquickjs::Error, timed_out: bool) -> ScriptError {
    if timed_out {
        return ScriptError::plain("the script ran past its time limit");
    }
    let caught = ctx.catch();
    let Some(x) = caught.as_exception() else {
        return ScriptError::plain(e.to_string());
    };
    let message = x.message().unwrap_or_else(|| e.to_string());
    let line = x
        .get::<_, Option<i32>>("lineNumber")
        .ok()
        .flatten()
        .or_else(|| {
            // `at <eval> (file:LINE:COL)`: the first position in the stack.
            let stack = x.stack()?;
            let at = stack.lines().next()?;
            let pos = at
                .rsplit_once('(')
                .map_or(at, |(_, p)| p)
                .trim_end_matches(')');
            pos.split(':').rev().nth(1)?.parse().ok()
        })
        .and_then(|n| u32::try_from(n).ok());
    let code = x.get::<_, Option<String>>("code").ok().flatten();
    ScriptError {
        message,
        line,
        code,
    }
}

/// Runs `code`. `host(op, args)` makes one operation call; the engine has already checked the
/// call budget and the argument size.
pub fn run(
    code: &str,
    lim: &Limits,
    host: impl FnMut(&str, Value) -> Result<Value, Refusal> + 'static,
) -> Run {
    let logs = Rc::new(RefCell::new(Vec::<String>::new()));
    let calls = Rc::new(Cell::new(0usize));
    let result = go(code, lim, host, &logs, &calls);
    Run {
        result,
        logs: logs.take(),
        calls: calls.get(),
    }
}

fn go(
    code: &str,
    lim: &Limits,
    host: impl FnMut(&str, Value) -> Result<Value, Refusal> + 'static,
    logs: &Rc<RefCell<Vec<String>>>,
    calls: &Rc<Cell<usize>>,
) -> Result<String, ScriptError> {
    let fail = |e: rquickjs::Error| ScriptError::plain(e.to_string());
    let rt = Runtime::new().map_err(fail)?;
    rt.set_memory_limit(lim.memory);
    rt.set_max_stack_size(lim.stack);
    let deadline = Instant::now() + lim.time();
    rt.set_interrupt_handler(Some(Box::new(move || Instant::now() > deadline)));
    let ctx = Context::custom::<(
        intrinsic::Eval,
        intrinsic::Json,
        intrinsic::Promise,
        intrinsic::Proxy,
    )>(&rt)
    .map_err(fail)?;
    let (budget, host) = (lim.calls, RefCell::new(host));
    let (n, l) = (calls.clone(), logs.clone());
    let bytes = Cell::new(0usize);
    ctx.with(|ctx: Ctx| -> Result<String, ScriptError> {
        let g = ctx.globals();
        let op = Function::new(ctx.clone(), move |name: String, args: String| -> String {
            n.set(n.get() + 1);
            let refuse = |r: Refusal| {
                serde_json::json!({"err": {"code": r.code, "message": r.message}}).to_string()
            };
            if n.get() > budget {
                return refuse(Refusal::new(
                    "too_many_calls",
                    "the script made too many operation calls",
                ));
            }
            if args.len() > MAX_CALL_ARGS {
                return refuse(Refusal::new(
                    "args_too_large",
                    "the arguments are too large",
                ));
            }
            let args: Value = match serde_json::from_str(&args) {
                Ok(v @ Value::Object(_)) => v,
                _ => return refuse(Refusal::new("bad_args", "the arguments are an object")),
            };
            // A reentrant call cannot happen (the bridge is synchronous), but never panic on it.
            let Ok(mut host) = host.try_borrow_mut() else {
                return refuse(Refusal::new("busy", "one operation at a time"));
            };
            match host(&name, args) {
                Ok(v) => serde_json::json!({"ok": v}).to_string(),
                Err(r) => refuse(r),
            }
        })
        .map_err(fail)?;
        g.set("__op", op).map_err(fail)?;
        let log = Function::new(ctx.clone(), move |m: String| {
            let mut all = l.borrow_mut();
            if bytes.get() <= MAX_CONSOLE {
                bytes.set(bytes.get() + m.len() + 1);
                all.push(super::cap(&m, MAX_CONSOLE));
                if bytes.get() > MAX_CONSOLE {
                    all.push("[console output truncated]".to_owned());
                }
            }
        })
        .map_err(fail)?;
        g.set("__log", log).map_err(fail)?;
        ctx.eval::<(), _>(PRELUDE).map_err(fail)?;
        let src = format!(
            "(r => r === undefined ? 'null' : JSON.stringify(r))((function(){{{code}\n}})())"
        );
        ctx.eval::<String, _>(src)
            .map_err(|e| describe(&ctx, &e, Instant::now() > deadline))
    })
}
