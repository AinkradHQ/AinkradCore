//! The root-side host helper, slice 1 (D2 socket-activated, D3 a separate small binary).
//!
//! systemd starts one process per connection with the socket as standard input. The order on
//! every connection is fixed:
//!
//! 1. the peer's uid (`SO_PEERCRED`) must be the uid of `ainkrad` from `/etc/passwd`, checked
//!    **before a single byte is read**; any other peer gets `forbidden_peer`;
//! 2. a 2 s deadline for the whole request line (not per read, so a slow-loris client gets no
//!    more time by sending a byte at a time);
//! 3. one line, at most 4 KiB, parsed into a typed action with unknown fields refused;
//! 4. limits, lock, act, log, answer.
//!
//! A helper killed between answering `restart_*` and running `systemctl` leaves a repeat of that
//! id answering `accepted` with no `failed` line (the answer is written first, on purpose, so it
//! reaches the client even when the restart tears the Core down). Repeats of a request are silent.
//!
//! No network, no tokio, no shell, no installed binary is ever run: the only processes are
//! `systemctl` and `journalctl`, with fixed argv and an empty environment (`exec.rs`).

mod actlog;
mod exec;
mod limits;
mod logs;
mod redact;
mod state;
mod status;
mod wire;

use std::fs::TryLockError;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

pub use exec::{Exec, JOURNALCTL, Out, Real, SYSTEMCTL};
pub use wire::{Action, Class, Code, REGISTRY, Request, parse};

const READ_DEADLINE: Duration = Duration::from_secs(2);
const WRITE_DEADLINE: Duration = Duration::from_secs(5);
const STATE_DIR: &str = "/var/lib/ainkrad-host";
const BIN_DIR: &str = "/usr/local/bin";
const LOCK: &str = "lock";

/// Everything the helper reads from outside. `production()` is the only constructor the binary
/// uses; the fields are public so tests can point them at a temporary directory.
pub struct Ctx {
    pub state_dir: PathBuf,
    pub bin_dir: PathBuf,
    /// The uid of `ainkrad`; `None` (user missing, or uid 0) refuses every peer.
    pub ainkrad_uid: Option<u32>,
    /// Who must own the binaries and the bin dir (root).
    pub owner_uid: u32,
    pub exec: Box<dyn Exec>,
    pub now: Box<dyn Fn() -> u64 + Send + Sync>,
    /// How many files `status` hashed (the cache test reads it).
    pub hashes: AtomicUsize,
}

impl Ctx {
    pub fn production() -> Self {
        Self {
            state_dir: STATE_DIR.into(),
            bin_dir: BIN_DIR.into(),
            ainkrad_uid: passwd_uid("ainkrad"),
            owner_uid: 0,
            exec: Box::new(Real),
            now: Box::new(unix_now),
            hashes: AtomicUsize::new(0),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The uid of `name` in `/etc/passwd` (the first matching line, as `getpwnam` would pick). Not
/// uid 0: a root `ainkrad` entry would turn the peer check into "root only".
pub fn passwd_uid(name: &str) -> Option<u32> {
    let bytes = state::read_capped(std::path::Path::new("/etc/passwd"), 1 << 20).ok()?;
    uid_in(&String::from_utf8_lossy(&bytes), name)
}

pub fn uid_in(passwd: &str, name: &str) -> Option<u32> {
    let uid = passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then(|| f.nth(1)?.parse::<u32>().ok())?
    })?;
    (uid != 0).then_some(uid)
}

enum Read1 {
    Line(Vec<u8>),
    Refused,
}

/// Reads one line of at most `MAX_REQUEST` bytes inside the deadline. Bytes after the newline,
/// a longer line, EOF first, or a timeout are refused.
fn read_line(stream: &mut UnixStream, total: &mut usize) -> Read1 {
    let deadline = Instant::now() + READ_DEADLINE;
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return Read1::Refused;
        }
        // Never read past one byte beyond the cap: the line, its newline, and one more to refuse.
        let want = chunk.len().min(wire::MAX_REQUEST + 2 - buf.len());
        let n = match stream.read(&mut chunk[..want]) {
            Ok(0) | Err(_) => return Read1::Refused,
            Ok(n) => n,
        };
        *total += n;
        buf.extend_from_slice(&chunk[..n]);
        if let Some(nl) = buf.iter().position(|b| *b == b'\n') {
            if nl != buf.len() - 1 || nl > wire::MAX_REQUEST {
                return Read1::Refused;
            }
            buf.truncate(nl);
            return Read1::Line(buf);
        }
        if buf.len() > wire::MAX_REQUEST {
            return Read1::Refused;
        }
    }
}

fn respond(stream: &mut UnixStream, mut bytes: Vec<u8>) {
    if bytes.len() > wire::MAX_RESPONSE {
        bytes = wire::err(None, Code::Failed, None);
    }
    let _ = stream.set_write_timeout(Some(WRITE_DEADLINE));
    let _ = stream.write_all(&bytes);
}

/// What a request left in `actions.log`: mutating actions and every refusal, never a read that
/// worked.
struct Trail<'a> {
    ctx: &'a Ctx,
    peer: u32,
}

impl Trail<'_> {
    fn log(
        &self,
        result: &str,
        action: &str,
        id: Option<&str>,
        actor: Option<&wire::Actor>,
        extra: &str,
    ) -> std::io::Result<()> {
        let mut fields = format!("peer={} id={}", self.peer, id.unwrap_or("-"));
        match actor {
            Some(a) => fields.push_str(&format!(" claimed_by_core={}#{}", a.device, a.audit_seq)),
            None => fields.push_str(" claimed_by_core=-"),
        }
        fields.push_str(extra);
        let line = actlog::Line {
            now: (self.ctx.now)(),
            result,
            action,
            fields,
            durable: result == "accepted",
        };
        // Files first: the root-action record is the one that must exist. A repeat of a request
        // that was never recorded must not read "accepted".
        let written = match result {
            // A repeat does nothing, so it leaves nothing: no file, no journal line.
            "deduped" => return Ok(()),
            "accepted" | "failed" => {
                let kept = actlog::append_to(&self.ctx.state_dir, actlog::MUTATIONS, &line);
                // The shared log is a convenience.
                let _ = actlog::append(&self.ctx.state_dir, &line);
                kept
            }
            _ => actlog::append(&self.ctx.state_dir, &line),
        };
        if matches!(result, "accepted" | "failed") {
            // The journal keeps root actions even if the files cannot. Never `eprintln!`: it
            // panics when stderr is closed (EPIPE), which would kill the helper mid-action.
            let _ = writeln!(
                std::io::stderr().lock(),
                "ainkrad-host: {} {} {} {}",
                line.now,
                line.result,
                line.action,
                line.fields
            );
        }
        written
    }
}

/// Serves one connection and returns how many request bytes it read (zero for a wrong peer).
pub fn serve(ctx: &Ctx, mut stream: UnixStream) -> usize {
    let mut read = 0;
    let peer = ainkrad_sys::peer_uid(stream.as_fd()).ok();
    let allowed = matches!((peer, ctx.ainkrad_uid), (Some(p), Some(a)) if p == a);
    let trail = Trail {
        ctx,
        peer: peer.unwrap_or(u32::MAX),
    };
    if !allowed {
        let _ = trail.log("refused", "-", None, None, " code=forbidden_peer");
        respond(&mut stream, wire::err(None, Code::ForbiddenPeer, None));
        return 0;
    }
    let line = match read_line(&mut stream, &mut read) {
        Read1::Line(l) => l,
        Read1::Refused => {
            let _ = trail.log(
                "refused",
                "-",
                None,
                None,
                &format!(" code=bad_request bytes={read}"),
            );
            respond(&mut stream, wire::err(None, Code::BadRequest, None));
            return read;
        }
    };
    match wire::parse(&line) {
        Err(r) => {
            let class = if r.class_b { " class=b" } else { "" };
            let _ = trail.log(
                "refused",
                r.action.unwrap_or("-"),
                r.id.as_deref(),
                r.actor.as_ref(),
                &format!(" code={}{class}", r.code.as_str()),
            );
            respond(&mut stream, wire::err(r.id.as_deref(), r.code, None));
        }
        Ok(req) => {
            handle(ctx, &trail, &req, &mut stream);
        }
    }
    read
}

/// A refusal's answer, logged. A refusal that cannot be logged is still answered.
fn refuse(trail: &Trail, req: &Request, code: Code, retry_after: Option<u64>) -> Vec<u8> {
    let extra = retry_after.map_or(String::new(), |s| format!(" retry_after={s}"));
    let _ = trail.log(
        "refused",
        req.action.name(),
        Some(&req.id),
        Some(&req.actor),
        &format!(" code={}{extra}", code.as_str()),
    );
    wire::err(Some(&req.id), code, retry_after)
}

fn handle(ctx: &Ctx, trail: &Trail, req: &Request, stream: &mut UnixStream) {
    if req.action.mutating() {
        return mutate(ctx, trail, req, stream);
    }
    if let Err(wait) = read_limit(ctx, req.action.name()) {
        return respond(stream, refuse(trail, req, Code::RateLimited, Some(wait)));
    }
    let result = match &req.action {
        Action::Status => status::status(ctx),
        Action::Logs(l) => logs::logs(ctx, l),
        _ => Err(Code::UnknownAction),
    };
    respond(
        stream,
        match result {
            Ok(v) => wire::ok(&req.id, v), // a read that worked is not logged
            Err(code) => refuse(trail, req, code, None),
        },
    );
}

/// Read rate limits (`status` 120/min, `logs` 60/min) in `reads.json`. Reads must work when the
/// state is bad, so a file that cannot be read or written never refuses anything. The read-modify-
/// write runs under a blocking lock of its own (`reads.lock`, held across two fsyncs, with no timeout of its own; it relies on the unit's `RuntimeMaxSec=30`), so parallel
/// instances neither lose counts nor share a temp file mid-write.
fn read_limit(ctx: &Ctx, action: &str) -> Result<(), u64> {
    const FILE: &str = "reads.json";
    let max = if action == "status" { 120 } else { 60 };
    let now = (ctx.now)();
    let lock = state::open_lock(&ctx.state_dir, "reads.lock").ok();
    if let Some(l) = &lock {
        let _ = l.lock();
    }
    let mut seen: std::collections::BTreeMap<String, Vec<u64>> =
        state::read_capped(&ctx.state_dir.join(FILE), 64 * 1024)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
    let times = seen.entry(action.to_owned()).or_default();
    // Entries from a clock that has since stepped back are dropped, not waited for.
    times.retain(|t| *t <= now && now - *t < 60);
    if times.len() >= max {
        return Err(times
            .iter()
            .min()
            .map_or(1, |t| (t + 60).saturating_sub(now).max(1)));
    }
    times.push(now);
    let _ = serde_json::to_vec(&seen).map(|b| state::write_atomic(&ctx.state_dir, FILE, &b));
    Ok(())
}

/// `restart_core` and `restart_runner`: lock, fail-closed limits, dedupe, rate limit, log, then
/// **answer, then act**: `{"accepted":true}` is written before `systemctl` is run, so the answer
/// reaches the client even when the restart tears the Core down. If systemctl then fails, the
/// failure is logged and a repeat of the same id answers `failed`.
fn mutate(ctx: &Ctx, trail: &Trail, req: &Request, stream: &mut UnixStream) {
    let name = req.action.name();
    let say = |stream: &mut UnixStream, b: Vec<u8>| respond(stream, b);
    if !state::dir_safe(&ctx.state_dir, ctx.owner_uid) {
        return say(stream, refuse(trail, req, Code::StateUnavailable, None));
    }
    let Ok(lock) = state::open_lock(&ctx.state_dir, LOCK) else {
        return say(stream, refuse(trail, req, Code::StateUnavailable, None));
    };
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return say(stream, refuse(trail, req, Code::Busy, None)),
        Err(TryLockError::Error(_)) => {
            return say(stream, refuse(trail, req, Code::StateUnavailable, None));
        }
    }
    let now = (ctx.now)();
    let Ok(mut limits) = limits::load(&ctx.state_dir) else {
        return say(stream, refuse(trail, req, Code::StateUnavailable, None));
    };
    if let Some(done) = limits.dedupe(&req.id, now) {
        if done.action != name {
            return say(stream, refuse(trail, req, Code::BadRequest, None));
        }
        let _ = trail.log("deduped", name, Some(&req.id), Some(&req.actor), "");
        return say(
            stream,
            if done.accepted {
                wire::ok(&req.id, json!({"accepted": true}))
            } else {
                wire::err(Some(&req.id), Code::Failed, None)
            },
        );
    }
    if name == "restart_runner" {
        match status::runner_installed(ctx) {
            Some(true) => {}
            Some(false) => return say(stream, refuse(trail, req, Code::NotInstalled, None)),
            None => return say(stream, refuse(trail, req, Code::Failed, None)),
        }
    }
    if let Err(wait) = limits.check(name, now) {
        return say(stream, refuse(trail, req, Code::RateLimited, Some(wait)));
    }
    // Counted and logged before it runs: no unlogged root action, and a failed write is a refusal.
    limits.record(&req.id, name, now);
    if limits::save(&ctx.state_dir, &limits).is_err() {
        return say(stream, refuse(trail, req, Code::StateUnavailable, None));
    }
    if trail
        .log("accepted", name, Some(&req.id), Some(&req.actor), "")
        .is_err()
    {
        // Counted but not run: a repeat of this id must not claim it was accepted, and the
        // journal and shared log (if they work) say why.
        limits.mark_failed(&req.id);
        let _ = trail.log(
            "failed",
            name,
            Some(&req.id),
            Some(&req.actor),
            " code=state_unavailable",
        );
        let _ = limits::save(&ctx.state_dir, &limits);
        return say(
            stream,
            wire::err(Some(&req.id), Code::StateUnavailable, None),
        );
    }
    say(stream, wire::ok(&req.id, json!({"accepted": true})));
    let unit = if name == "restart_core" {
        "ainkrad-core.service"
    } else {
        "ainkrad-runner.service"
    };
    let args = ["--no-block", "--no-ask-password", "restart", unit].map(String::from);
    if !ctx.exec.run(SYSTEMCTL, &args, 4096).is_ok_and(|o| o.ok) {
        limits.mark_failed(&req.id);
        let _ = limits::save(&ctx.state_dir, &limits);
        let _ = trail.log(
            "failed",
            name,
            Some(&req.id),
            Some(&req.actor),
            " code=failed",
        );
    }
}
