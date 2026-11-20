//! The pure parts of `job.run` (E15-4): request checks, redaction across chunk edges, signal names,
//! and the sandbox's and the command's environments.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{ErrorCode, JobRun, StreamError, valid_secret_var, wire_path_problem};

use super::super::toolchains;

const MAX_ARGS: usize = 1024;
const MAX_ARG_BYTES: usize = 256 * 1024;
const MAX_ENV: usize = 256;
const MAX_ENV_VALUE: usize = 32 * 1024;
const MAX_PREPARE: usize = 8;

fn invalid(why: impl Into<String>) -> StreamError {
    StreamError::new(ErrorCode::InvalidArgs, why)
}

fn argv_problem(argv: &[String]) -> Option<&'static str> {
    if argv.is_empty() || argv[0].is_empty() {
        return Some("argv is empty");
    }
    if argv.len() > MAX_ARGS || argv.iter().map(String::len).sum::<usize>() > MAX_ARG_BYTES {
        return Some("argv is too long");
    }
    argv.iter()
        .any(|a| a.contains('\0'))
        .then_some("argv holds a NUL")
}

/// What is wrong with a request that no runner state could fix (`invalid_args` or `path_refused`).
pub fn problem(req: &JobRun) -> Option<StreamError> {
    let bad = |why: &str| Some(invalid(why));
    if let Some(why) = argv_problem(&req.argv) {
        return bad(why);
    }
    if req.prepare.len() > MAX_PREPARE || req.prepare.iter().any(|p| argv_problem(p).is_some()) {
        return bad("a prepare command is not valid");
    }
    let id = req.job.as_str();
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return bad("the job id is not valid");
    }
    if req.project <= 0 {
        return bad("the job names no project");
    }
    if !req.cache.is_empty() && super::sync::safe_name(&req.cache).is_none() {
        return bad("the cache name is not valid");
    }
    if !req.cwd_rel.is_empty()
        && (wire_path_problem(&req.cwd_rel).is_some() || req.cwd_rel.chars().any(char::is_control))
    {
        return Some(StreamError::new(
            ErrorCode::PathRefused,
            "cwd_rel is not a wire path",
        ));
    }
    if req.env.len() > MAX_ENV
        || req
            .env
            .iter()
            .any(|(k, v)| !valid_secret_var(k) || v.len() > MAX_ENV_VALUE || v.contains('\0'))
    {
        return bad("the environment holds a name or value a job may not set");
    }
    let mut names = std::collections::BTreeSet::new();
    if req.secrets.len() > MAX_ENV
        || req
            .secrets
            .iter()
            .any(|s| !valid_secret_var(&s.name) || s.lease.is_empty() || !names.insert(&s.name))
    {
        return bad("a secret has an invalid or repeated name");
    }
    if req.timeout_ms == Some(0) {
        return bad("timeout_ms is 0");
    }
    None
}

/// Whether `cwd` is `root` or inside it, once both are real paths (links resolved).
pub fn within(root: &Path, cwd: &Path) -> bool {
    match (root.canonicalize(), cwd.canonicalize()) {
        (Ok(r), Ok(c)) => c.starts_with(r) && c.is_dir(),
        _ => false,
    }
}

/// The signal a process ended by, by name.
pub fn signal_name(n: i32) -> String {
    match n {
        1 => "HUP".into(),
        2 => "INT".into(),
        3 => "QUIT".into(),
        6 => "ABRT".into(),
        9 => "KILL".into(),
        11 => "SEGV".into(),
        13 => "PIPE".into(),
        15 => "TERM".into(),
        n => format!("SIG{n}"),
    }
}

/// The number a `signal` frame names, for the ones a job may be sent.
pub(super) fn signal_number(name: &str) -> Option<i32> {
    match name {
        "HUP" => Some(1),
        "INT" => Some(2),
        "TERM" => Some(15),
        "KILL" => Some(9),
        _ => None,
    }
}

/// `bytes` through `r`, holding back an incomplete UTF-8 tail in `carry` for the next chunk so a
/// character or a secret cut by a read boundary is still masked whole.
pub fn redact_chunk(r: &mut Redactor, carry: &mut Vec<u8>, bytes: &[u8]) -> Vec<u8> {
    carry.extend_from_slice(bytes);
    let mut out = String::new();
    loop {
        match std::str::from_utf8(carry) {
            Ok(s) => {
                out.push_str(&r.stream_text(s));
                carry.clear();
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                if valid > 0 {
                    let good = std::str::from_utf8(&carry[..valid]).unwrap_or_default();
                    out.push_str(&r.stream_text(good));
                }
                match e.error_len() {
                    // A character cut by the chunk: wait for the rest.
                    None => {
                        carry.drain(..valid);
                        break;
                    }
                    Some(n) => {
                        out.push('\u{fffd}');
                        carry.drain(..valid + n);
                    }
                }
            }
        }
    }
    out.into_bytes()
}

/// The sandbox's variables for a job (the same contract as `ProcessSandbox::prepare`, with limits
/// sized for builds and the toolchains mounted read-only). Pure.
#[allow(clippy::too_many_arguments)]
pub(super) fn sandbox_vars(
    state: &Path,
    job_dir: &Path,
    ro: &[PathBuf],
    wall: Duration,
    proxy: Vec<(String, OsString)>,
) -> Vec<(String, OsString)> {
    let own_tmp = std::env::temp_dir();
    let own_tmp = own_tmp.canonicalize().unwrap_or(own_tmp);
    let limit = |name: &str, default: u64| {
        std::env::var(format!("AINKRAD_JOB_{name}"))
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(default)
            .to_string()
    };
    let mut v: Vec<(String, OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_STATE".into(), state.into()),
        (
            "AINKRAD_SANDBOX_SECRETS".into(),
            job_dir.join("secrets").into(),
        ),
        ("AINKRAD_SANDBOX_TMP".into(), job_dir.join("tmp").into()),
        ("AINKRAD_SANDBOX_HIDE_TMP".into(), own_tmp.into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), "filtered".into()),
        (
            "AINKRAD_SANDBOX_PGID_FILE".into(),
            job_dir.join("pgid").into(),
        ),
        (
            "AINKRAD_SANDBOX_RO".into(),
            std::env::join_paths(ro).unwrap_or_default(),
        ),
        (
            "AINKRAD_SANDBOX_WALL".into(),
            wall.as_secs().clamp(1, 86_400).to_string().into(),
        ),
        // Builds, unlike an agent turn: many processes, big files, a lot of memory and disk (KiB).
        (
            "AINKRAD_SANDBOX_PROCESSES".into(),
            limit("PROCESSES", 4096).into(),
        ),
        ("AINKRAD_SANDBOX_CPU".into(), limit("CPU", 86_400).into()),
        (
            "AINKRAD_SANDBOX_FILE".into(),
            limit("FILE", 8 * 1024 * 1024).into(),
        ),
        (
            "AINKRAD_SANDBOX_MEMORY".into(),
            limit("MEMORY", 16 * 1024 * 1024).into(),
        ),
        (
            "AINKRAD_SANDBOX_DISK".into(),
            limit("DISK", 64 * 1024 * 1024).into(),
        ),
    ];
    v.extend(proxy);
    v
}

/// The variables the command sees: its home and temp, the toolchains', then what the job set, then
/// its secrets. Nothing is inherited from the runner.
pub(super) fn command_env(
    home: &Path,
    tmp: &Path,
    tools: &toolchains::JobTools,
    head: Option<&str>,
    req: &JobRun,
    secrets: &[(String, String)],
) -> Vec<(String, OsString)> {
    let mut path: Vec<PathBuf> = tools.path.clone();
    path.extend(
        [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
            "/opt/homebrew/bin",
        ]
        .map(PathBuf::from),
    );
    let mut env: Vec<(String, OsString)> = vec![
        (
            "PATH".into(),
            std::env::join_paths(path).unwrap_or_default(),
        ),
        ("HOME".into(), home.into()),
        ("TMPDIR".into(), tmp.into()),
        ("LANG".into(), "C".into()),
        ("CI".into(), "1".into()),
    ];
    if let Some(h) = head {
        env.push(("AINKRAD_GIT_HEAD".into(), h.into()));
    }
    env.extend(tools.env.iter().map(|(k, v)| (k.clone(), v.into())));
    env.extend(req.env.iter().map(|(k, v)| (k.clone(), v.into())));
    env.extend(secrets.iter().map(|(k, v)| (k.clone(), v.into())));
    env
}

/// Removes a job's folder when dropped, however the job ended.
pub(super) struct JobDir(pub(super) PathBuf);

impl Drop for JobDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
