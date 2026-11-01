//! A run along its agent's fallback chain (E15.3): the job's own (harness, model, account),
//! then `job.fallbacks` in order. A turn that fails as model unavailable, rate-limited or out
//! of quota (`ainkrad_harness::classify`), or an entry whose account token cannot be read,
//! moves the run to the next entry: a `Report::Fallback` tells the server first, and the new
//! entry starts a fresh session in the same working dir. Tokens and cost add up across
//! entries in one meter, so the cap and the reported totals are the run's. With the chain
//! spent, the run fails with every reason. A class the server's `fallback.on_*` settings turn
//! off (`RunLimits`, 1.20) fails the run where it is.

use ainkrad_harness::agy::Agy;
use ainkrad_harness::claude::Claude;
use ainkrad_harness::codex::Codex;
use ainkrad_harness::opencode::OpenCode;
use ainkrad_harness::{ErrorClass, Harness, Meter, Spec, classify};
use ainkrad_proto::runner::{Outcome, PermissionMode, RunToken};
use tokio::sync::mpsc;

use super::files::RunFiles;
use super::turn::failed;
use super::{HARNESSES, HarnessExecutor};
use crate::{Job, Report};

/// The job's chain as jobs: its own entry, then each fallback in its place.
pub(super) fn routes(job: &Job) -> Vec<Job> {
    let mut all = vec![Job {
        fallbacks: vec![],
        ..job.clone()
    }];
    all.extend(job.fallbacks.iter().map(|r| Job {
        harness: r.harness.clone(),
        model: r.model.clone(),
        account: r.account.clone(),
        fallbacks: vec![],
        resume_session: None,
        ..job.clone()
    }));
    all
}

/// Whether `harness` is a server a later run can reuse (`Harness::LONG_LIVED`).
fn long_lived(harness: &str) -> bool {
    match harness {
        "codex" => <Codex as Harness>::LONG_LIVED,
        "opencode" => <OpenCode as Harness>::LONG_LIVED,
        _ => false,
    }
}

/// `harness/model`, as reasons name an entry.
fn named(job: &Job) -> String {
    format!("{}/{}", job.harness, job.model)
}

impl HarnessExecutor {
    /// Works `job` along its chain to the run's outcome.
    pub(super) async fn work_routes(
        &self,
        job: &Job,
        token: &RunToken,
        reports: &mpsc::Sender<Report>,
    ) -> Outcome {
        let mut credentials = self
            .credentials
            .lock()
            .expect("credentials lock")
            .remove(&job.run)
            .unwrap_or_default()
            .into_iter();
        let session = self
            .sessions
            .lock()
            .expect("sessions lock")
            .remove(&job.run);
        let chain = routes(job);
        let (mut meter, mut reasons) = (Meter::default(), vec![]);
        let mut pending: Option<(&str, String)> = None;
        let mut last = None;
        for (i, entry) in chain.iter().enumerate() {
            let credential = match credentials.next().unwrap_or(Ok(None)) {
                Ok(c) => c,
                Err(why) => {
                    // Skipped, never started: the server hears of the entry that failed.
                    reasons.push(format!("{}: no_account: {why}", named(entry)));
                    continue;
                }
            };
            if let Some((class, reason)) = pending.take() {
                let fallback = Report::Fallback {
                    harness: entry.harness.clone(),
                    model: entry.model.clone(),
                    account: entry.account.as_ref().map(|a| a.id),
                    class: class.to_owned(),
                    reason,
                };
                let _ = reports.send(fallback).await;
                meter.new_session();
            }
            let session = if i == 0 { session.clone() } else { None };
            let outcome = self
                .work_entry(entry, token, session, credential, reports, &mut meter)
                .await;
            let Outcome::Failed {
                reason,
                fingerprint,
            } = &outcome
            else {
                return outcome;
            };
            // Only a turn the harness itself failed says why (`<harness>:<code>`); a crash or
            // a setup failure is no reason to try another model.
            let class = match fingerprint.as_deref().and_then(|f| f.split_once(':')) {
                Some((harness, code)) if harness == entry.harness => classify(code, reason),
                _ => ErrorClass::Permanent,
            };
            // The server's settings may keep a class from falling back (1.20).
            let allowed = job.limits.is_none_or(|l| l.falls_back_on(class.as_str()));
            if !class.falls_back() || !allowed {
                return outcome;
            }
            reasons.push(format!("{}: {}: {reason}", named(entry), class.as_str()));
            pending = Some((class.as_str(), reason.clone()));
            last = Some(outcome);
        }
        match (chain.len(), last) {
            (1, Some(only)) => only,
            _ => failed(
                format!(
                    "every model in the fallback chain failed: {}",
                    reasons.join("; ")
                ),
                "fallback_exhausted",
            ),
        }
    }

    /// One entry: its files, its spec, its harness, to its outcome.
    async fn work_entry(
        &self,
        job: &Job,
        token: &RunToken,
        session: Option<String>,
        credential: Option<super::Credential>,
        reports: &mpsc::Sender<Report>,
        meter: &mut Meter,
    ) -> Outcome {
        // A session that was handed no token (no MCP) gets no MCP config.
        let mcp = self
            .mcp_url
            .as_deref()
            .filter(|_| !token.expose().is_empty());
        // A Linux session with no network (`deny`, the default) or only the egress proxy (`filtered`)
        // reaches the MCP route through a bridge.
        let network = |want: &str| {
            cfg!(target_os = "linux")
                && self
                    .run_env
                    .lock()
                    .expect("run env lock")
                    .get(&job.run)
                    .is_some_and(|e| {
                        ainkrad_harness::last_env(e, "AINKRAD_SANDBOX_NETWORK")
                            .is_some_and(|v| v == want)
                    })
        };
        let filtered = network("filtered");
        let denied = network("deny") || filtered;
        let bridged = mcp.filter(|_| denied).and_then(crate::mcp_bridge::parse);
        let mcp = match (&bridged, mcp) {
            (Some((_, local)), _) => Some((local.as_str(), token)),
            (None, url) => url.map(|url| (url, token)),
        };
        let private = self.work_root.join("private");
        let instructions = job.instructions.as_deref();
        // Removed when this future ends or is dropped (a cancelled run).
        // A harness that may be kept warm reads its files from its agent's stable dir (E15.6).
        // A session with no network is never kept warm (`turn.rs`: isolated runs are not), and
        // its MCP bridge lives and dies with this run, so its files are always the run's own.
        let name = match self.limits(job).warm_max > 0 && long_lived(&job.harness) && !denied {
            true => format!("warm-{}-{}", job.agent, job.harness),
            false => format!("run-{}", job.run),
        };
        let files = match RunFiles::write(&private, &name, &job.harness, mcp, instructions) {
            Ok(files) => files,
            Err(e) => return failed(format!("writing the run's files: {e}"), "run_files"),
        };
        let mut bridge = None;
        let mut bridge_env: Vec<(String, std::ffi::OsString)> = Vec::new();
        if let Some((target, _)) = bridged {
            let sock = files.dir.join("mcp.sock");
            match crate::mcp_bridge::start(&sock, target, self.mcp_tls.clone()) {
                Ok(b) => bridge = Some(b),
                Err(e) => return failed(format!("the MCP bridge: {e}"), "run_files"),
            }
            let exe = std::env::current_exe().unwrap_or_default();
            bridge_env.extend([
                ("AINKRAD_SANDBOX_MCP_SOCK".to_owned(), sock.into()),
                ("AINKRAD_SANDBOX_MCP_FWD".to_owned(), exe.into()),
                (
                    "AINKRAD_SANDBOX_MCP_PORT".to_owned(),
                    crate::mcp_bridge::FORWARD_PORT.to_string().into(),
                ),
            ]);
        }
        // The egress proxy of a filtered run: no policy or no socket refuses the run, never opens it.
        let mut egress = None;
        if filtered {
            let Some(policy) = self.egress.clone() else {
                return failed("this runner has no egress policy".to_owned(), "sandbox");
            };
            let sock = crate::egress::socket_in(&files.dir);
            match crate::egress::start(&sock, policy) {
                Ok(p) => egress = Some(p),
                Err(e) => return failed(format!("the egress proxy: {e}"), "sandbox"),
            }
            let exe = self
                .forwarder
                .clone()
                .or_else(|| std::env::current_exe().ok())
                .unwrap_or_default();
            bridge_env.extend(crate::egress::sandbox_env(&sock, &exe));
        }
        let config_dir = match self.config_dir(job) {
            Ok(dir) => dir,
            Err(why) => return failed(why, "account"),
        };
        if let Err(e) = std::fs::create_dir_all(&config_dir) {
            return failed(format!("{}: {e}", config_dir.display()), "account");
        }
        let mut env_allow = self.env_allow.clone();
        // The runner's `--env` first. A variable set more than once takes its LAST value (the
        // sandbox builder and `Command::envs` both read it that way), so everything the runner
        // sets after this wins over it. No `AINKRAD_*` name comes from `--env` at all: those are
        // the runner's own control variables (the sandbox and its network mode).
        let mut env: Vec<(String, std::ffi::OsString)> = self
            .harness_env
            .iter()
            .filter(|(name, _)| !name.starts_with("AINKRAD_"))
            .map(|(name, value)| (name.clone(), value.into()))
            .collect();
        env.extend(self.workspaces.env());
        // The run's own (E2-07.2), after the runner's: a session's secret wins.
        if let Some(own) = self.run_env.lock().expect("run env lock").get(&job.run) {
            env.extend(own.iter().map(|(n, v)| (n.clone(), v.into())));
        }
        env.extend(bridge_env);
        // Every worktree of a repo builds into its one shared cache (E15.9).
        if let (Some(_), Some(issue)) = (&job.workspace, job.issue) {
            env.extend(self.workspaces.cache_env(issue, &job.trees()));
        }
        // An account's login or token only, never the runner's own; and an isolated agent
        // session never gets the runner's keys either (it can send them anywhere the
        // network policy allows): a session's key must be a leased secret.
        let isolated = env.iter().any(|(n, _)| n == "AINKRAD_SANDBOX");
        env_allow = allowed_env(
            env_allow,
            &self.secret_env,
            job.account.is_some() || isolated,
        );
        if let Some(c) = credential {
            env.push((c.var, c.value.into()));
        }
        // The `citadel` CLI first on `PATH` (E15.18). The run token stays out of the
        // environment, as before: the CLI reads the run's private token file.
        if let Some(token) = &files.token {
            env.push(("CITADEL_RUN_TOKEN_FILE".to_owned(), token.into()));
        }
        if let Some(bin) = &files.bin {
            let mut path = std::ffi::OsString::from(bin);
            if let Some(rest) = std::env::var_os("PATH") {
                path.push(":");
                path.push(rest);
            }
            env.push(("PATH".to_owned(), path));
        }
        let default_model = HARNESSES
            .iter()
            .find(|(name, _)| *name == job.harness)
            .map_or("", |(_, model)| model);
        let spec = Spec {
            program: self.bins.get(&job.harness).cloned(),
            cwd: self.cwd(job),
            process_dir: None,
            model: if job.model.is_empty() {
                default_model.to_owned()
            } else {
                job.model.clone()
            },
            config_dir,
            env_allow,
            env,
            session_id: session,
            // `start` refused a sandboxed policy on a runner that is not.
            sandboxed: job.policy.mode == PermissionMode::Sandboxed && self.sandboxed,
            accept_edits: job.policy.mode == PermissionMode::AcceptEdits,
            instructions: files.instructions.clone(),
            mcp_config: files.mcp_config.clone(),
            backend: self.backend.clone(),
        };
        let reports = reports.clone();
        let _bridge = bridge; // held until the run ends
        let _egress = egress;
        let outcome = match job.harness.as_str() {
            "claude" => self.work::<Claude>(job, spec, reports, meter).await,
            "codex" => self.work::<Codex>(job, spec, reports, meter).await,
            "opencode" => self.work::<OpenCode>(job, spec, reports, meter).await,
            "agy" => self.work::<Agy>(job, spec, reports, meter).await,
            other => failed(
                format!("harness {other:?} is not supported"),
                "harness_start",
            ),
        };
        if denied {
            return no_network_note(outcome, filtered);
        }
        outcome
    }
}

/// A failure that looks like an unreachable model API, said plainly for a session with no network.
fn no_network_note(outcome: Outcome, filtered: bool) -> Outcome {
    let why = if filtered {
        "this session reaches only the destinations AINKRAD_AGENT_EGRESS_ALLOW and AINKRAD_AGENT_EGRESS_HOSTS list, through a CONNECT proxy"
    } else {
        "this session has no network: AINKRAD_AGENT_NETWORK=deny is the Linux default, so the harness cannot reach its model API; stage 1 uses a local mock model"
    };
    const SIGNS: [&str; 7] = [
        "connect",
        "network",
        "dns",
        "resolve",
        "unreachable",
        "timed out",
        "fetch failed",
    ];
    match outcome {
        Outcome::Failed {
            reason,
            fingerprint,
        } if SIGNS.iter().any(|s| reason.to_lowercase().contains(s)) => Outcome::Failed {
            reason: format!("{reason} ({why})"),
            fingerprint,
        },
        other => other,
    }
}

/// The runner variables a harness may inherit: without its own secrets when the run has an
/// account or is isolated.
fn allowed_env(mut allow: Vec<String>, secret: &[String], strip_secrets: bool) -> Vec<String> {
    if strip_secrets {
        allow.retain(|name| !secret.contains(name));
    }
    allow
}

#[cfg(test)]
mod allowed_env_tests {
    use super::allowed_env;

    #[test]
    fn an_isolated_run_never_inherits_the_runners_keys() {
        let allow = vec!["PATH".to_owned(), "ANTHROPIC_API_KEY".to_owned()];
        let secret = vec!["ANTHROPIC_API_KEY".to_owned()];
        assert_eq!(allowed_env(allow.clone(), &secret, true), ["PATH"]);
        assert_eq!(allowed_env(allow, &secret, false).len(), 2);
    }
}
