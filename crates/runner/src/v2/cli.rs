//! The v2 command line: `ainkrad-runner pair`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use super::client::Client;
use super::key::State;
use super::pair::{Credential, pair, parse_qr};

pub const PAIR_USAGE: &str = "usage:
  ainkrad-runner pair <core-url> --code <ABCDE-FGHJK> [--state <dir>] [--ca <pem>]
  ainkrad-runner pair --qr '<ainkrad-pair:v1?…>' [--state <dir>] [--ca <pem>]

Enrols this runner with the Core as a `runner` device (one-time code or QR from an approver),
pins the Core's identity, and keeps its key and enrolment in <dir> (default
$HOME/.ainkrad-runner/core; both files mode 0600). <core-url> is https://<host>[:port]
(http:// only to a loopback host). Compare the SAS it prints with the approver's screen.
--ca trusts that PEM certificate instead of the public roots (a test Core).";

/// The runner's state directory: `--state`, else `$HOME/.ainkrad-runner/core`.
pub fn state_dir(flag: Option<&str>) -> State {
    State(flag.map_or_else(
        || {
            let home = std::env::var_os("HOME").map_or_else(PathBuf::new, PathBuf::from);
            home.join(".ainkrad-runner/core")
        },
        PathBuf::from,
    ))
}

/// A TLS client config that trusts only the PEM certificates in `path`.
pub fn tls_from_ca(path: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("{path}: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{path}: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for c in certs {
        roots.add(c).map_err(|e| format!("{path}: {e}"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// `--flag value` pairs after the positional arguments.
pub fn flag<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1])
}

pub async fn pair_main(args: &[&str]) -> ExitCode {
    let usage = || {
        eprintln!("{PAIR_USAGE}");
        ExitCode::from(2)
    };
    let (base, credential) = match (args.first(), flag(args, "--code"), flag(args, "--qr")) {
        (Some(url), Some(code), None) if !url.starts_with("--") => {
            ((*url).to_owned(), Credential::Code(code.to_owned()))
        }
        (_, None, Some(qr)) => match parse_qr(qr) {
            Some((base, core_fp, secret)) => (base, Credential::Qr { secret, core_fp }),
            None => return usage(),
        },
        _ => return usage(),
    };
    let tls = match flag(args, "--ca").map(tls_from_ca).transpose() {
        Ok(tls) => tls,
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            return ExitCode::FAILURE;
        }
    };
    let state = state_dir(flag(args, "--state"));
    let client = match Client::new(&base, tls) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            return ExitCode::FAILURE;
        }
    };
    let show = |sas: &str| {
        println!("Claimed. Check that the approving device shows this code, then approve:");
        println!("    {sas}");
    };
    match pair(&client, &state, credential, show, Duration::from_secs(2)).await {
        Ok(e) => {
            println!(
                "Paired as {} with the Core {}; saved in {}",
                e.device_id,
                e.core_fp,
                state.0.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            ExitCode::FAILURE
        }
    }
}

pub const CONNECT_USAGE: &str = "usage:
  ainkrad-runner connect [--state <dir>] [--ca <pem>] [--enable-exec] [--enable-pty]
                         [--enable-agents]

Serves the Core it paired with (`ainkrad-runner pair`) over protocol v2, reconnecting with a
jittered backoff and resuming commands in flight. Stops on SIGTERM or Ctrl-C; commands still
running are killed. It offers only `noop` unless --enable-exec is given: `exec.run` lets the
Core run any program as this runner's user (bounded in time and output, with an empty
environment), so turn it on only where that is wanted. --enable-pty offers terminals: a shell
as this runner's user, each held by a detached ainkrad-ptyhost (found next to this binary, or
at $AINKRAD_PTYHOST) that outlives the runner; their sockets are in <dir>/terminals. A
runner started as root gives root shells.
--enable-agents offers agent sessions (the harnesses on PATH, as this runner's user, unconfined
until E2-09): transcripts in <dir>/agents, delivered secrets in $XDG_RUNTIME_DIR (else
<dir>/secrets), emptied at start.
Exit status: 0 stopped (SIGTERM, Ctrl-C); 1 an error that retrying cannot fix (state, URL, TLS);
2 usage; 6 rejected by the Core: this runner was revoked (close 4001), or the Core refused it
as an unknown or revoked device (auth_failed) 3 dials in a row; pair it again. Network errors,
5xx and 429 are retried, never an exit.";

/// `connect`'s exit status when the Core rejects this runner (as ctl's for a revoked device).
pub const EXIT_REJECTED: u8 = 6;

fn agents_enabled(args: &[&str]) -> bool {
    args.contains(&"--enable-agents")
}

pub async fn connect_main(args: &[&str]) -> ExitCode {
    let run_enabled = args.contains(&"--enable-exec");
    let pty_enabled = args.contains(&"--enable-pty");
    let agents_enabled = agents_enabled(args);
    let args: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !matches!(*a, "--enable-exec" | "--enable-pty" | "--enable-agents"))
        .collect();
    let args = args.as_slice();
    if !args.len().is_multiple_of(2) || args.chunks(2).any(|f| !matches!(f[0], "--state" | "--ca"))
    {
        eprintln!("{CONNECT_USAGE}");
        return ExitCode::from(2);
    }
    let tls = match flag(args, "--ca").map(tls_from_ca).transpose() {
        Ok(tls) => tls,
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            return ExitCode::FAILURE;
        }
    };
    let state = state_dir(flag(args, "--state"));
    let exec = Arc::new(super::ExecDriver::new(
        super::ExecConfig {
            run_enabled,
            ..super::ExecConfig::default()
        },
        ainkrad_proto::redact::Redactor::new(),
    ));
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            return ExitCode::FAILURE;
        }
    };
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        stop.send_replace(true);
    });
    let pty = pty_enabled.then(|| {
        Arc::new(super::PtyDriver::new(super::PtyConfig {
            enabled: true,
            ..super::PtyConfig::new(state.0.join("terminals"))
        }))
    });
    let agents = match agents_enabled.then(|| agents(&state.0, core_url(&state))) {
        None => None,
        Some(a) => match a.await {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("ainkrad-runner: agents: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    match super::daemon::from_state(&state, exec, pty, agents, tls, stopping).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e @ super::client::LinkError::Rejected(_)) => {
            eprintln!("ainkrad-runner: {e}");
            ExitCode::from(EXIT_REJECTED)
        }
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The Core's address as `ws(s)://` (what `core_mcp_url` takes), from the enrolment.
fn core_url(state: &super::key::State) -> Option<String> {
    let url = super::key::Enrolment::load(&state.enrolment()).ok()?.url;
    url.strip_prefix("https://")
        .map(|r| format!("wss://{r}"))
        .or_else(|| url.strip_prefix("http://").map(|r| format!("ws://{r}")))
}

/// The agent driver over `<state>/agents`, driving the real harnesses (`HarnessExecutor`).
/// Delivered secrets go to `$XDG_RUNTIME_DIR` (a tmpfs on most Linux hosts), in a dir named
/// for this state dir so two runners never sweep each other's; else `<state>/secrets`.
///
/// Agents are opt-in and always process-isolated. The Core's `secrets.mode` gate remains
/// authoritative; unavailable isolation refuses the start instead of falling back.
/// Secret files require a runtime filesystem (tmpfs/ramdisk); persistent fallback is refused.
/// As the v1 runner does: the work root is outside the home and under no harness instruction
/// file (`check_roots`), and each harness's version is probed; only an installed one the
/// compat matrix does not refuse gets a slot, so any other is refused at `agent.start`.
async fn agents(
    state: &std::path::Path,
    core_url: Option<String>,
) -> Result<super::agent::AgentDriver, String> {
    let secrets = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(run) => {
            let tag =
                ring::digest::digest(&ring::digest::SHA256, state.as_os_str().as_encoded_bytes());
            let tag: String = tag.as_ref()[..6]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            PathBuf::from(run).join(format!("ainkrad-runner-{tag}"))
        }
        None => state.join("secrets"),
    };
    let tag = ring::digest::digest(&ring::digest::SHA256, state.as_os_str().as_encoded_bytes());
    let tag: String = tag.as_ref()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let work = std::env::temp_dir().join(format!("ainkrad-agent-runs-{tag}"));
    let mut executor = crate::HarnessExecutor::new(work, state.join("agents-config"));
    // The Citadel MCP server at the Core this runner is enrolled with: without it a run's harness
    // is given no MCP config, whatever token the Core minted.
    executor.mcp_url = core_url.and_then(|u| crate::core_mcp_url(&u));
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    executor.check_roots(&home)?;
    let mut config = super::agent::AgentConfig::new(state.join("agents"), secrets.clone());
    for (name, version) in executor.probe(Duration::from_secs(10)).await {
        let verdict = ainkrad_harness::compat::check(&name, Some(&version), &Default::default());
        if !verdict.refused {
            config.slots.insert(name, config.capacity);
        }
    }
    if config.slots.is_empty() {
        return Err("no harness is installed in a version the compat matrix takes".to_owned());
    }
    super::agent::AgentDriver::new(config, executor)
        .map(|d| {
            d.with_sandbox(Arc::new(super::sandbox::ProcessSandbox::new(
                state.to_path_buf(),
                secrets,
            )))
        })
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::agents_enabled;

    #[test]
    fn agents_are_off_by_default() {
        assert!(!agents_enabled(&["--state", "/tmp/runner"]));
        assert!(agents_enabled(&["--enable-agents"]));
    }
}
