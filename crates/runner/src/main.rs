use std::process::ExitCode;
use std::time::Duration;

use std::path::PathBuf;

use ainkrad_runner::{Config, HarnessExecutor, mac};
use tokio::signal::unix::SignalKind;

/// How long a harness gets to answer `--version` at start.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a run in flight may take to end once the runner is told to stop (SIGTERM, Ctrl-C);
/// under launchd's default 20 s before SIGKILL.
const STOP_GRACE: Duration = Duration::from_secs(15);

const USAGE: &str = "usage:
  ainkrad-runner <server-url> [--tags <a,b,…>] [--key-file <path>]
                 [--git-name <name>] [--git-email <email>] [--env <KEY=VAL>…]
  ainkrad-runner install-launchd <server-url> --key-file <path> [runner flags…] [--load]
  ainkrad-runner uninstall-launchd [--unload]
  ainkrad-runner pair …          (protocol v2: enrol with an Ainkrad Core; `pair` alone for help)
  ainkrad-runner connect …       (protocol v2: serve the paired Core; `connect --help`)

The runner key comes from CITADEL_RUNNER_KEY, or else from --key-file; never from the
command line. The URL is wss://<server>/runner/v1/connect (ws:// only to loopback).
Runs are worked by the job's harness: an issue of a project with a repo in its git worktree
$TMPDIR/citadel-runs/worktrees/issue-<id> (reused across runs), any other run in
$TMPDIR/citadel-runs/run-<id>. The work root must sit outside $HOME. git never prompts and
reads no user config; a repo that needs auth gets it from the program CITADEL_GIT_ASKPASS
names (it answers git's Username/Password prompts). Agents commit as the identity
--git-name/--git-email set, kept in the runner-owned git config
$HOME/.ainkrad-runner/git/config; the runner refuses to start without one. Each harness has its own config dir
$HOME/.ainkrad-runner/<harness>, logged in once:
  claude  `CLAUDE_CONFIG_DIR=$HOME/.ainkrad-runner/claude claude /login`, or set
          CLAUDE_CODE_OAUTH_TOKEN (`claude setup-token`) or ANTHROPIC_API_KEY for the runner
  codex   `CODEX_HOME=$HOME/.ainkrad-runner/codex codex login`
  opencode nothing for the free `opencode/*` models; others
          `XDG_DATA_HOME=$HOME/.ainkrad-runner/opencode/data opencode auth login`
  agy     `HOME=$HOME/.ainkrad-runner/agy agy`; agy cannot ask before acting, so it runs
          only when CITADEL_RUNNER_SANDBOXED=1 says this runner's workspaces are sandboxes
          and the project's permission policy is sandboxed
A run the server gives a provider account (`ainkrad-core-server account add`) uses that account's
config dir $HOME/.ainkrad-runner/<config-dir> (default accounts/<label>; log it in there, as
above) and, when the account names a credential file, the token in
$HOME/.ainkrad-runner/credentials/<file> (mode 0600), read when the run starts and passed
only in the harness's environment; the runner's own CLAUDE_CODE_OAUTH_TOKEN/ANTHROPIC_API_KEY
are then withheld. A missing file fails the run with the path in its reason.
Each run's harness reaches the server's MCP tools at <server>/mcp/v1 (https://, or http:// to
loopback) with the run's token, from a 0600 config file in $TMPDIR/citadel-runs/private/run-<id>
removed when the run ends. Tool calls follow each project's permission policy (default: ask);
the Citadel MCP tools always go ahead, as the token scopes them. One outside it waits for
a reviewer's approval on the server, and is denied after 15 minutes without one. Projects
whose runs must be sandboxed run only with CITADEL_RUNNER_SANDBOXED=1.
At start each harness's `--version` is probed. A missing harness is not offered; one at a
version this runner was not built for marks the runner unhealthy and is not offered either.
Without --tags a Mac offers `macos`, plus `xcode` when `xcode-select -p` finds Xcode.
install-launchd writes a launchd user agent (~/Library/LaunchAgents/com.ainkrad.ainkrad-runner
.plist; KeepAlive; logs in ~/Library/Logs/ainkrad-runner) that runs this runner with the
given flags; the key must come from --key-file, never the plist. It prints the launchctl
commands that load it, and runs them only with --load. uninstall-launchd removes the plist
and prints the command that stops the agent, run only with --unload.
--env KEY=VAL (repeatable) sets a variable for every harness process, e.g. a longer shell
timeout (BASH_MAX_TIMEOUT_MS=1200000) or a shared CARGO_HOME. The runner's own variables and
secrets (CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_API_KEY) are never set this way.";

/// The command line.
#[derive(Default)]
struct Args {
    url: String,
    tags: Vec<String>,
    key_file: Option<String>,
    git_name: Option<String>,
    git_email: Option<String>,
    env: Vec<(String, String)>,
}

/// `KEY=VAL` as `--env` takes it; `None` without a `=` or with an empty key.
fn env_pair(pair: &str) -> Option<(String, String)> {
    let (key, value) = pair.split_once('=')?;
    (!key.is_empty()).then(|| (key.to_owned(), value.to_owned()))
}

/// `None` on anything it does not know.
fn parse(args: &[&str]) -> Option<Args> {
    let [url, flags @ ..] = args else {
        return None;
    };
    let mut parsed = Args {
        url: (*url).to_owned(),
        ..Args::default()
    };
    for pair in flags.chunks(2) {
        match pair {
            ["--tags", list] => parsed.tags = list.split(',').map(str::to_owned).collect(),
            ["--key-file", path] => parsed.key_file = Some((*path).to_owned()),
            ["--git-name", name] => parsed.git_name = Some((*name).to_owned()),
            ["--git-email", email] => parsed.git_email = Some((*email).to_owned()),
            ["--env", pair] => parsed.env.push(env_pair(pair)?),
            _ => return None,
        }
    }
    Some(parsed)
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(PathBuf::new, PathBuf::from)
}

/// Prints each command, and runs it when `run`; an install's leading `bootout` may fail.
fn launchctl(commands: &[Vec<String>], run: bool) -> ExitCode {
    for (n, cmd) in commands.iter().enumerate() {
        println!("{}", cmd.join(" "));
        if !run {
            continue;
        }
        let status = std::process::Command::new(&cmd[0]).args(&cmd[1..]).status();
        // The first `bootout` of an install fails when nothing was loaded yet.
        let lenient = n == 0 && commands.len() > 1;
        if !status.is_ok_and(|s| s.success()) && !lenient {
            eprintln!("ainkrad-runner: {} failed", cmd.join(" "));
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn install_launchd(rest: &[&str]) -> ExitCode {
    let load = rest.contains(&"--load");
    let mut flags: Vec<String> = rest
        .iter()
        .filter(|a| **a != "--load")
        .map(|a| (*a).to_owned())
        .collect();
    let refs: Vec<&str> = flags.iter().map(String::as_str).collect();
    let Some(parsed) = parse(&refs) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(key_file) = parsed.key_file else {
        eprintln!(
            "ainkrad-runner: install-launchd needs --key-file; the key never goes in the plist"
        );
        return ExitCode::from(2);
    };
    // launchd starts the agent in `/`: the key file must be absolute.
    let key_file = match std::fs::canonicalize(&key_file) {
        Ok(path) => path.display().to_string(),
        Err(e) => {
            eprintln!("ainkrad-runner: {key_file}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(at) = flags.iter().position(|f| f == "--key-file") {
        flags[at + 1] = key_file;
    }
    let installed = std::env::current_exe().and_then(|exe| mac::install(&home(), &exe, &flags));
    match installed {
        Ok((path, commands)) => {
            eprintln!("wrote {}; to load it:", path.display());
            launchctl(&commands, load)
        }
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            ExitCode::FAILURE
        }
    }
}

fn uninstall_launchd(unload: bool) -> ExitCode {
    match mac::uninstall(&home()) {
        Ok((existed, commands)) => {
            let what = if existed { "removed" } else { "no" };
            eprintln!(
                "{what} {}; to stop the agent:",
                mac::plist_path(&home()).display()
            );
            launchctl(&commands, unload)
        }
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["pair", rest @ ..] => return ainkrad_runner::v2::cli::pair_main(rest).await,
        ["connect", rest @ ..] => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .init();
            return ainkrad_runner::v2::cli::connect_main(rest).await;
        }
        ["install-launchd", rest @ ..] => return install_launchd(rest),
        ["uninstall-launchd"] => return uninstall_launchd(false),
        ["uninstall-launchd", "--unload"] => return uninstall_launchd(true),
        _ => {}
    }
    let Some(mut args) = parse(&args) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let key = match (std::env::var("CITADEL_RUNNER_KEY"), &args.key_file) {
        (Ok(key), _) => key,
        (Err(_), Some(path)) => match std::fs::read_to_string(path) {
            Ok(key) => key.trim().to_owned(),
            Err(e) => {
                eprintln!("ainkrad-runner: reading {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
        (Err(_), None) => {
            eprintln!("ainkrad-runner: set CITADEL_RUNNER_KEY or pass --key-file\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if args.tags.is_empty() {
        args.tags = mac::default_tags();
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let home = home();
    let mut executor = HarnessExecutor::new(
        std::env::temp_dir().join("citadel-runs"),
        home.join(".ainkrad-runner"),
    )
    .with_env(args.env);
    executor.sandboxed = std::env::var("CITADEL_RUNNER_SANDBOXED").as_deref() == Ok("1");
    executor.mcp_url = ainkrad_runner::mcp_url(&args.url);
    executor.workspaces.askpass = std::env::var_os("CITADEL_GIT_ASKPASS").map(PathBuf::from);
    if let Err(why) = executor.check_roots(&home) {
        eprintln!("ainkrad-runner: {why}");
        return ExitCode::FAILURE;
    }
    let identity = executor
        .workspaces
        .set_identity(args.git_name.as_deref(), args.git_email.as_deref());
    match identity.await {
        Ok((name, email)) => tracing::info!(%name, %email, "agents commit as"),
        Err(why) => {
            eprintln!("ainkrad-runner: {why}");
            return ExitCode::FAILURE;
        }
    }
    let config = Config {
        url: args.url,
        key,
        tags: args.tags,
        harnesses: executor.probe(PROBE_TIMEOUT).await,
        // Where its launchd agent logs (E3.11), unless `CITADEL_RUNNER_LOG` says otherwise.
        log: std::env::var_os("CITADEL_RUNNER_LOG")
            .map(PathBuf::from)
            .or_else(|| {
                cfg!(target_os = "macos")
                    .then(|| home.join("Library/Logs/ainkrad-runner/runner.log"))
            }),
    };
    // On SIGTERM as on Ctrl-C the executor is dropped, which kills its harnesses, warm ones
    // included (E15.6): none outlives the runner.
    let mut term = match tokio::signal::unix::signal(SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            eprintln!("ainkrad-runner: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let daemon = ainkrad_runner::run_until(config, executor, stopping);
    tokio::pin!(daemon);
    tokio::select! {
        e = &mut daemon => {
            eprintln!("ainkrad-runner: {e}");
            return ExitCode::FAILURE;
        }
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    // No new work; a run in flight gets a short grace to end and be acknowledged. One still
    // going after it is dropped here and retried by the server once its lease expires.
    stop.send_replace(true);
    match tokio::time::timeout(STOP_GRACE, daemon).await {
        Ok(ainkrad_runner::Error::Stopped) => ExitCode::SUCCESS,
        Ok(e) => {
            eprintln!("ainkrad-runner: {e}");
            ExitCode::FAILURE
        }
        Err(_) => {
            tracing::warn!("a run was still going after {STOP_GRACE:?}; the server retries it");
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn env_flags_are_key_value_pairs_and_a_bare_name_is_refused() {
        let parsed = parse(&[
            "wss://x/runner/v1/connect",
            "--env",
            "BASH_MAX_TIMEOUT_MS=1200000",
            "--env",
            "CARGO_HOME=/opt/cargo=home",
        ])
        .expect("two --env pairs parse");
        assert_eq!(
            parsed.env,
            [
                ("BASH_MAX_TIMEOUT_MS".to_owned(), "1200000".to_owned()),
                ("CARGO_HOME".to_owned(), "/opt/cargo=home".to_owned()),
            ]
        );
        assert!(parse(&["wss://x", "--env", "FOO"]).is_none(), "no =");
        assert!(parse(&["wss://x", "--env", "=bar"]).is_none(), "no key");
        assert!(parse(&["wss://x", "--env"]).is_none(), "no value");
    }
}
