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
                         [--enable-agents] [--terminal-sandbox=on|off]
                         [--terminal-hide <path>]… [--terminal-user <account>]
                         [--terminal-network=host|none|filtered]

Serves the Core it paired with (`ainkrad-runner pair`) over protocol v2, reconnecting with a
jittered backoff and resuming commands in flight. Stops on SIGTERM or Ctrl-C; commands still
running are killed. It offers only `noop` unless --enable-exec is given: `exec.run` lets the
Core run any program as this runner's user (bounded in time and output, with an empty
environment), so turn it on only where that is wanted. --enable-pty offers terminals: a shell
as this runner's user, each held by a detached ainkrad-ptyhost (found next to this binary, or
at $AINKRAD_PTYHOST) that outlives the runner; their sockets are in <dir>/terminals. A
runner started as root gives root shells.
SECURITY: the `terminal` scope is ADMIN-EQUIVALENT for anything this runner's user can read
(its key in <dir>, delivered agent secrets, harness logins), because a terminal is a shell as
that user, unless the terminal sandbox is on. It is on by default: each shell runs with this
runner's private paths (<dir>, $HOME/.ainkrad-runner, the secrets dir, the agents' work root)
hidden, and in its own process namespace on Linux (bubblewrap; macOS: Seatbelt), while the
rest of the host stays usable. The runner refuses to start with --enable-pty when the sandbox
cannot run. --terminal-sandbox=off removes that protection and is logged loudly at start: use
it only on a host whose `terminal` devices are trusted as admins. Residual with it on: the
shell is the same uid, so it reaches what that uid owns outside the hidden paths (the user's
own files, ssh keys, docker, ssh-agent); a shell can still edit its own startup files and,
on macOS, signal other processes of the same user; the runner binary, its pty host and the
user's systemd/launchd launcher dirs are read-only to it (created when missing), the user's
systemd/D-Bus sockets (/run/user/<uid>) are hidden on Linux, and on macOS inspecting other
processes, launchctl and launchd's XPC domain are denied (best effort: Seatbelt cannot stop
every route to launchd); a Core's default state dirs (/var/lib/ainkrad, /var/lib/ainkrad-relay,
/run/ainkrad) are hidden without a flag; a signal sent through the API goes to the sandbox
wrapper. --terminal-hide <path> (repeatable) hides a Core kept elsewhere (its admin.sock);
running the Core and the runner as different users is better.
--terminal-user <account> (E2-25) runs every shell, and its sandbox wrapper, as that other,
unprivileged account through `sudo -n`, so the `terminal` scope no longer reaches what the
runner's user owns. It needs --enable-pty, the sandbox on (it is refused with
--terminal-sandbox=off), a state dir only the runner's user can enter (made 0700 at start) and an account that exists and is neither root nor
the runner's user, plus a sudoers rule that lets the runner's user run the sandbox launcher
(bwrap, or sandbox-exec on macOS) and /usr/bin/true as that account without a password. The
runner checks all of this at start and refuses to start when any of it is missing; once on,
a shell is never started as the runner's user (a failing sudo means the terminal fails). Shells
start in / and with sudo's cleaned environment. See the security posture runbook.
--terminal-network=host|none|filtered (KAN-416) sets the network of every shell; it needs the sandbox.
`host` (the default) is the host's own network, unfiltered: the accepted scope of an admin-equivalent
terminal. `none` gives each shell a network namespace with no interface (Linux: bubblewrap
--unshare-net, which also closes the host's abstract unix sockets; macOS: Seatbelt deny network*).
`filtered` (Linux only, not with --terminal-user) is `none` plus HTTPS_PROXY to the egress proxy
that agent sessions use, with the same allow policy from AINKRAD_AGENT_EGRESS_ALLOW/_HOSTS/_PORTS
(and AINKRAD_AGENT_NETWORK=filtered when --enable-agents is on); the runner proves the filter at start.
It refuses to start, never falls back to `host`, when the mode cannot be given. In a filtered or
none shell only HTTPS through the proxy works: no DNS, ssh, ping or plain TCP.
--enable-agents offers agent sessions (the harnesses on PATH, as this runner's user, each
in a process sandbox, refused when it cannot run): transcripts in <dir>/agents, delivered secrets in $XDG_RUNTIME_DIR (else
<dir>/secrets), emptied at start.
Exit status: 0 stopped (SIGTERM, Ctrl-C); 1 an error that retrying cannot fix (state, URL, TLS);
2 usage; 6 rejected by the Core: this runner was revoked (close 4001), or the Core refused it
as an unknown or revoked device (auth_failed) 3 dials in a row; pair it again. Network errors,
5xx and 429 are retried, never an exit.";

/// `connect`'s exit status when the Core rejects this runner (as ctl's for a revoked device).
pub const EXIT_REJECTED: u8 = 6;

/// `--terminal-sandbox=on|off` (default on); `None` for any other value or a repeat.
fn terminal_sandbox(args: &[&str]) -> Option<bool> {
    let mut it = args
        .iter()
        .filter_map(|a| a.strip_prefix("--terminal-sandbox="));
    let value = match it.next() {
        None => return Some(true),
        Some("on") => true,
        Some("off") => false,
        Some(_) => return None,
    };
    it.next().is_none().then_some(value)
}

/// `--terminal-network=host|none|filtered` (KAN-416); absent is `host`. `None` for a bad or repeated value.
fn terminal_network(args: &[&str]) -> Option<&'static str> {
    let mut it = args
        .iter()
        .filter_map(|a| a.strip_prefix("--terminal-network="));
    let value = match it.next() {
        None | Some("host") => "host",
        Some("none") => "none",
        Some("filtered") => "filtered",
        Some(_) => return None,
    };
    it.next().is_none().then_some(value)
}

fn agents_enabled(args: &[&str]) -> bool {
    args.contains(&"--enable-agents")
}

pub async fn connect_main(args: &[&str]) -> ExitCode {
    let run_enabled = args.contains(&"--enable-exec");
    let pty_enabled = args.contains(&"--enable-pty");
    let agents_enabled = agents_enabled(args);
    let Some(terminal_sandbox) = terminal_sandbox(args) else {
        eprintln!("{CONNECT_USAGE}");
        return ExitCode::from(2);
    };
    let Some(terminal_network) = terminal_network(args) else {
        eprintln!("{CONNECT_USAGE}");
        return ExitCode::from(2);
    };
    // A network the sandbox cannot give is refused, never fallen back to the host's; the
    // filtered proxy's socket is private to the runner's user, so it is not offered with
    // --terminal-user (another uid could not reach it).
    if terminal_network != "host"
        && (!pty_enabled
            || !terminal_sandbox
            || (terminal_network == "filtered"
                && (!cfg!(target_os = "linux") || args.contains(&"--terminal-user"))))
    {
        eprintln!("{CONNECT_USAGE}");
        return ExitCode::from(2);
    }
    let args: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| {
            !matches!(*a, "--enable-exec" | "--enable-pty" | "--enable-agents")
                && !a.starts_with("--terminal-sandbox=")
                && !a.starts_with("--terminal-network=")
        })
        .collect();
    let args = args.as_slice();
    if !args.len().is_multiple_of(2)
        || args.chunks(2).any(|f| {
            !matches!(
                f[0],
                "--state" | "--ca" | "--terminal-hide" | "--terminal-user"
            )
        })
        || args.iter().filter(|a| **a == "--terminal-user").count() > 1
        || (args.contains(&"--terminal-user") && (!pty_enabled || !terminal_sandbox))
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
    // Held until the runner stops: the proxy terminals reach through their socket dir.
    let _terminal_proxy = if pty_enabled && terminal_network == "filtered" {
        match terminal_proxy(&state.0.join("terminal-egress")).await {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("ainkrad-runner: terminals: --terminal-network=filtered: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    if pty_enabled && !terminal_sandbox {
        let m = "terminal sandbox is OFF: a `terminal` device can read this runner's key, delivered secrets and harness logins; `terminal` scope is admin-equivalent on this host";
        eprintln!("ainkrad-runner: WARNING: {m}");
        tracing::warn!("{m}");
    }
    let terminal_user = flag(args, "--terminal-user").map(str::to_owned);
    let egress_dir = state.0.join("terminal-egress");
    let exe = std::env::current_exe().unwrap_or_default();
    let net = super::termbox::Net::parse(terminal_network, egress_dir.clone(), exe)
        .expect("a mode terminal_network accepted");
    if let Some(user) = &terminal_user
        && let Err(e) = super::termbox::probe_user(user, terminal_sandbox, &net)
            .and_then(|()| super::termbox::private_state(&state.0))
    {
        eprintln!("ainkrad-runner: terminals: --terminal-user: {e}");
        return ExitCode::FAILURE;
    }
    if pty_enabled
        && terminal_sandbox
        && let Err(e) = super::termbox::probe(&net)
    {
        eprintln!("ainkrad-runner: terminals: {e}");
        return ExitCode::FAILURE;
    }
    // Created now, so they are hidden from every terminal that ever opens (see `prepare`).
    let hidden = terminal_sandbox.then(|| {
        super::termbox::hidden_paths(
            &state.0,
            &args
                .windows(2)
                .filter(|w| w[0] == "--terminal-hide")
                .map(|w| PathBuf::from(w[1]))
                .collect::<Vec<_>>(),
        )
    });
    if let Some(h) = &hidden
        && pty_enabled
        && let Err(e) = super::termbox::prepare(h)
    {
        eprintln!("ainkrad-runner: terminals: {e}");
        return ExitCode::FAILURE;
    }
    let host = ainkrad_ptyhost::client::find_host_binary()
        .unwrap_or_else(|| PathBuf::from("ainkrad-ptyhost"));
    let pty = pty_enabled.then(|| {
        let d = Arc::new(super::PtyDriver::new(super::PtyConfig {
            enabled: true,
            hide: hidden.clone(),
            readonly: super::termbox::readonly_paths(&host),
            user: terminal_user.clone(),
            net: net.clone(),
            ..super::PtyConfig::new(state.0.join("terminals"))
        }));
        d.spawn_budget_loop();
        d
    });
    if agents_enabled && std::env::var("AINKRAD_AGENT_NETWORK").is_ok_and(|v| v == "allow") {
        let m = "AINKRAD_AGENT_NETWORK=allow: agent sessions without secrets get the HOST network (cloud metadata, LAN, loopback services); use only on a stage-1 host with no instance role and nothing on loopback";
        eprintln!("ainkrad-runner: WARNING: {m}");
        tracing::warn!("{m}");
    }
    let agents = match agents_enabled.then(|| agents(&state.0, core_url(&state), tls.clone())) {
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

/// Where this runner keeps delivered secrets (`$XDG_RUNTIME_DIR/ainkrad-runner-<tag>`, else
/// `<state>/secrets`) and the agents' work root (`<tmp>/ainkrad-agent-runs-<tag>`); the tag is
/// derived from the state dir so two runners never share either.
pub fn runtime_paths(state: &std::path::Path) -> [PathBuf; 2] {
    let tag = ring::digest::digest(&ring::digest::SHA256, state.as_os_str().as_encoded_bytes());
    let tag: String = tag.as_ref()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let secrets = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(run) => PathBuf::from(run).join(format!("ainkrad-runner-{tag}")),
        None => state.join("secrets"),
    };
    [
        secrets,
        std::env::temp_dir().join(format!("ainkrad-agent-runs-{tag}")),
    ]
}

/// The Core's address as `ws(s)://` (what `core_mcp_url` takes), from the enrolment.
fn core_url(state: &super::key::State) -> Option<String> {
    let url = super::key::Enrolment::load(&state.enrolment()).ok()?.url;
    url.strip_prefix("https://")
        .map(|r| format!("wss://{r}"))
        .or_else(|| url.strip_prefix("http://").map(|r| format!("ws://{r}")))
}

/// `AINKRAD_AGENT_NETWORK=filtered` (E8a-01): parses the egress policy and proves the filter works
/// on this host before any session can use it. Any failure stops the agent driver from starting:
/// there is no fallback to another network mode. `true` when the filter is on and proven.
async fn egress_filter(executor: &mut crate::HarnessExecutor) -> Result<bool, String> {
    let mode = std::env::var("AINKRAD_AGENT_NETWORK").unwrap_or_default();
    if mode != "filtered" {
        let stray = ["ALLOW", "HOSTS", "PORTS"]
            .iter()
            .any(|k| std::env::var_os(format!("AINKRAD_AGENT_EGRESS_{k}")).is_some());
        return match stray {
            true => Err(
                "AINKRAD_AGENT_EGRESS_* is set but AINKRAD_AGENT_NETWORK is not filtered".into(),
            ),
            false => Ok(false),
        };
    }
    if !cfg!(target_os = "linux") {
        return Err("AINKRAD_AGENT_NETWORK=filtered is Linux only".into());
    }
    let policy =
        crate::egress::Policy::from_env()?.with_host_addresses(crate::egress::host_addresses()?);
    let exe =
        std::env::current_exe().map_err(|_| "cannot find the runner executable".to_owned())?;
    crate::egress::selftest(&policy, &exe)
        .await
        .map_err(|why| format!("the egress filter failed its start-up check: {why}"))?;
    let (cidrs, hosts, ports) = policy.counts();
    tracing::info!(
        cidrs,
        hosts,
        ports,
        "egress filter proven; agent sessions may run filtered"
    );
    executor.egress = Some(Arc::new(policy));
    Ok(true)
}

/// The egress proxy of `--terminal-network=filtered` (KAN-416): the policy of the agent sessions
/// (`AINKRAD_AGENT_EGRESS_*`), proven by the same start-up check, on a socket in `dir` (0700) that
/// the shells get bound in. A socket left by an earlier runner is replaced.
async fn terminal_proxy(dir: &std::path::Path) -> Result<crate::egress::Proxy, String> {
    use std::os::unix::fs::DirBuilderExt;
    let policy =
        crate::egress::Policy::from_env()?.with_host_addresses(crate::egress::host_addresses()?);
    let exe =
        std::env::current_exe().map_err(|_| "cannot find the runner executable".to_owned())?;
    crate::egress::selftest(&policy, &exe)
        .await
        .map_err(|why| format!("the egress filter failed its start-up check: {why}"))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let sock = crate::egress::socket_in(dir);
    let _ = std::fs::remove_file(&sock);
    crate::egress::start(&sock, Arc::new(policy)).map_err(|e| format!("{}: {e}", sock.display()))
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
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<super::agent::AgentDriver, String> {
    let [secrets, work] = runtime_paths(state);
    let mut executor = crate::HarnessExecutor::new(work, state.join("agents-config"));
    let egress_ready = egress_filter(&mut executor).await?;
    // The Citadel MCP server at the Core this runner is enrolled with: without it a run's harness
    // is given no MCP config, whatever token the Core minted.
    executor.mcp_url = core_url.and_then(|u| crate::core_mcp_url(&u));
    executor.mcp_tls = tls;
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
            let sandbox = super::sandbox::ProcessSandbox::new(state.to_path_buf(), secrets)
                .with_network(std::env::var("AINKRAD_AGENT_NETWORK").ok());
            d.with_sandbox(Arc::new(if egress_ready {
                sandbox.with_egress_ready()
            } else {
                sandbox
            }))
        })
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{agents_enabled, terminal_sandbox};

    #[test]
    fn the_terminal_network_is_the_host_unless_named_and_a_bad_value_is_refused() {
        use super::terminal_network;
        assert_eq!(terminal_network(&["--enable-pty"]), Some("host"));
        for ok in ["host", "none", "filtered"] {
            let flag = format!("--terminal-network={ok}");
            assert_eq!(terminal_network(&[flag.as_str()]), Some(ok));
        }
        for bad in [
            "--terminal-network=",
            "--terminal-network=allow",
            "--terminal-network=NONE",
        ] {
            assert_eq!(terminal_network(&[bad]), None, "{bad}");
        }
        assert_eq!(
            terminal_network(&["--terminal-network=none", "--terminal-network=host"]),
            None
        );
    }

    #[test]
    fn the_terminal_sandbox_is_on_unless_switched_off_explicitly() {
        assert_eq!(terminal_sandbox(&["--enable-pty"]), Some(true));
        assert_eq!(terminal_sandbox(&["--terminal-sandbox=on"]), Some(true));
        assert_eq!(terminal_sandbox(&["--terminal-sandbox=off"]), Some(false));
        for bad in [
            "--terminal-sandbox=",
            "--terminal-sandbox=0",
            "--terminal-sandbox=OFF",
        ] {
            assert_eq!(terminal_sandbox(&[bad]), None, "{bad}");
        }
        assert_eq!(
            terminal_sandbox(&["--terminal-sandbox=on", "--terminal-sandbox=off"]),
            None
        );
    }

    #[test]
    fn agents_are_off_by_default() {
        assert!(!agents_enabled(&["--state", "/tmp/runner"]));
        assert!(agents_enabled(&["--enable-agents"]));
    }
}
