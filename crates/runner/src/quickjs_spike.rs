//! E3.1 spike: a QuickJS context with no ambient authority. Only `ainkrad.op(name, args)` (sync, JSON in and
//! out) and `console.log` exist; no module loader, no `std`/`os`, memory and time capped.
use rquickjs::{Context, Ctx, Function, Runtime, context::intrinsic};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

pub struct Limits {
    pub memory: usize,
    pub stack: usize,
    pub time: Duration,
}

/// Runs `code` and returns its JSON-stringified result. `host(name, args_json) -> result_json`.
pub fn run(
    code: &str,
    lim: &Limits,
    host: impl Fn(&str, &str) -> String + 'static,
) -> Result<String, String> {
    let rt = Runtime::new().map_err(|e| e.to_string())?;
    rt.set_memory_limit(lim.memory);
    rt.set_max_stack_size(lim.stack);
    let deadline = Instant::now() + lim.time;
    rt.set_interrupt_handler(Some(Box::new(move || Instant::now() > deadline)));
    let ctx = Context::custom::<(intrinsic::Eval, intrinsic::Json, intrinsic::Promise)>(&rt)
        .map_err(|e| e.to_string())?; // Eval+JSON+Promise (Promise: a refused `import()` aborts the process without it)
    let logs = Rc::new(RefCell::new(Vec::<String>::new()));
    ctx.with(|ctx: Ctx| -> Result<String, String> {
        let g = ctx.globals();
        let op = Function::new(ctx.clone(), move |n: String, a: String| host(&n, &a)).map_err(|e| e.to_string())?;
        g.set("__op", op).map_err(|e| e.to_string())?;
        let l = logs.clone();
        let log = Function::new(ctx.clone(), move |m: String| l.borrow_mut().push(m)).map_err(|e| e.to_string())?;
        g.set("__log", log).map_err(|e| e.to_string())?;
        ctx.eval::<(), _>(
            "(function(op, log){ globalThis.ainkrad = Object.freeze({ op: (n, a) => JSON.parse(op(n, JSON.stringify(a ?? null))) });\
             globalThis.console = Object.freeze({ log: (...a) => log(a.map(String).join(' ')) });\
             })(__op, __log); delete globalThis.__op; delete globalThis.__log;",
        )
        .map_err(|e| e.to_string())?;
        let r: Result<String, _> = ctx.eval(format!("JSON.stringify((function(){{{code}\n}})())"));
        r.map_err(|e| match ctx.catch().as_exception() {
            Some(x) => x.message().unwrap_or_default(),
            None => e.to_string(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lim() -> Limits {
        Limits {
            memory: 16 << 20,
            stack: 256 << 10,
            time: Duration::from_millis(500),
        }
    }
    fn go(code: &str) -> Result<String, String> {
        run(code, &lim(), |n, a| {
            format!("{{\"op\":{n:?},\"args\":{a}}}")
        })
    }

    #[test]
    fn arithmetic_and_host_call() {
        assert_eq!(go("return 1+1"), Ok("2".into()));
        assert_eq!(
            go("return ainkrad.op('git.status', {n: 3})"),
            Ok("{\"op\":\"git.status\",\"args\":{\"n\":3}}".into())
        );
    }

    #[test]
    fn runaway_loop_is_interrupted() {
        let t = Instant::now();
        assert!(go("while(true){}").is_err());
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn memory_bomb_is_stopped() {
        let e = go("let a=[]; for(;;) a.push(new Array(100000).fill(1)); ").unwrap_err();
        assert!(e.to_lowercase().contains("memory"), "{e}");
        assert!(go("return 'x'.repeat(1<<28).length").is_err());
    }

    #[test]
    fn deep_recursion_is_a_plain_error() {
        assert!(go("function f(){return f()+1} return f()").is_err());
    }

    #[test]
    fn no_ambient_authority() {
        for c in [
            "return typeof require",
            "return typeof process",
            "return typeof fetch",
            "return typeof std",
            "return typeof os",
            "return typeof setTimeout",
            "return typeof XMLHttpRequest",
            "return typeof __op",
            "return typeof WebAssembly",
        ] {
            assert_eq!(go(c), Ok("\"undefined\"".into()), "{c}");
        }
        assert!(
            go("ainkrad.x = 1; return 1")
                .unwrap_err()
                .contains("not extensible")
        ); // frozen
        assert_eq!(go("return Object.keys(ainkrad)"), Ok("[\"op\"]".into()));
    }

    #[test]
    fn dynamic_import_is_refused() {
        assert!(go("import('os')").is_err());
    }

    #[test]
    fn import_meta_is_refused() {
        assert!(go("return import.meta").is_err());
    }

    #[test]
    fn console_log_is_captured_not_printed() {
        assert_eq!(go("console.log('a', 1); return 1"), Ok("1".into()));
    }
}
