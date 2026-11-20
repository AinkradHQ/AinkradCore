//! The answer to "run this command": local, or a heavy job placed on other hardware (E15-3).

use super::*;
use crate::heavy::decide::{Decision, Deps, decide as heavy_decide};
use crate::heavy::rules;
use crate::heavy::run::{Start, Started};
use serde_json::json;

/// What a request to run a command asks.
pub(super) struct Asked {
    pub(super) project: Option<i64>,
    pub(super) session: Option<String>,
    pub(super) terminal: Option<String>,
    pub(super) argv: Vec<String>,
    pub(super) cwd_rel: String,
    pub(super) env: BTreeMap<String, String>,
    pub(super) tty: bool,
    pub(super) net: JobNet,
}

/// The network a job placed elsewhere may have: never more than the sandbox that asked (E15 H2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum JobNet {
    /// A user's own request: the whole registry list.
    Registry,
    /// The sandbox has no network: the job is not sent, it runs inside that sandbox.
    Deny,
    /// Only these registry hosts (a `filtered` sandbox's list cut to the registry list).
    Hosts(Vec<String>),
}

impl JobNet {
    /// From the runner's report of the asking sandbox. Anything but `allow` and `filtered` is
    /// `Deny`, so an older runner that does not say keeps its sessions' jobs local.
    pub(super) fn of_sandbox(network: Option<&str>, hosts: Option<&[String]>) -> JobNet {
        match network {
            Some("allow") => JobNet::Registry,
            Some("filtered") => JobNet::Hosts(ainkrad_proto::v2::job_hosts_within(
                hosts.unwrap_or_default(),
            )),
            _ => JobNet::Deny,
        }
    }
}

pub(super) fn local(reason: &str, report: bool) -> Response {
    Json(JobLocal {
        verdict: "local".to_owned(),
        reason: reason.to_owned(),
        report,
    })
    .into_response()
}

/// Only the Core's own runner (the one the installer enrolled) may call the runner routes.
pub(super) async fn built_in(app: &App, caller: &Caller) -> Result<(), ApiError> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT device_id FROM core_pairings WHERE kind = 'runner' AND sas = ? AND device_id = ?",
    )
    .bind(crate::store::gov::LOCAL_ENROL_SAS)
    .bind(&caller.device.id)
    .fetch_optional(&app.pool)
    .await?;
    found.map(|_| ()).ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "not_built_in",
            "only the Core's own runner may call this",
        )
    })
}

/// Tiers 0 to 3 for one request. Placing and running a heavy job is `heavy/run.rs` (step 2).
pub(super) async fn answer(app: &App, a: Asked, from_runner: bool) -> Result<Response, ApiError> {
    if a.argv.is_empty() || a.argv.len() > 256 || a.argv[0].is_empty() {
        return Err(ApiError::bad_request(
            "argv is one to 256 words, the first a program",
        ));
    }
    if !a.cwd_rel.is_empty() && ainkrad_proto::v2::wire_path_problem(&a.cwd_rel).is_some() {
        return Ok(local("bad_cwd", false));
    }
    // A sandbox with no network keeps its commands: a job elsewhere would have registry egress.
    if a.net == JobNet::Deny {
        return Ok(local("network_deny", false));
    }
    // A session's commands belong to the project the session is in.
    let project = match (a.project, &a.session) {
        (None, Some(session)) => sqlx::query_scalar::<_, Option<i64>>(
            "SELECT project_id FROM core_agent_sessions WHERE id = ?",
        )
        .bind(session)
        .fetch_optional(&app.pool)
        .await?
        .flatten(),
        (p, _) => p,
    };
    let a = Asked { project, ..a };
    let ws = crate::heavy::workspace();
    let (rules, dir) = match a.project {
        Some(p) => {
            let toml = tokio::fs::read_to_string(ws.jobs_toml(p))
                .await
                .unwrap_or_default();
            let base = ws
                .project_meta(p)
                .parent()
                .map(std::path::Path::to_path_buf);
            (rules::parse_project(&toml), base)
        }
        None => (Vec::new(), None),
    };
    // The Decisions service, over the hub. The model must be this sure (a percent setting) before a
    // command it was asked about leaves the Core.
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let decider = crate::decisions::Service::for_app(app, ws.root(), home.as_deref());
    let min = crate::store::settings::value(
        &app.pool,
        ainkrad_core::settings::Key::DecisionsHeavyJobMinConfidence,
        ainkrad_core::settings::Scope::Server,
    )
    .await
    .unwrap_or(70);
    let deps = Deps {
        pool: &app.pool,
        decide: &decider,
        user: ainkrad_core::ids::UserId(1),
        min_confidence: min as f32 / 100.0,
    };
    let dir = dir.unwrap_or_default();
    Ok(
        match heavy_decide(&deps, a.project, &a.argv, a.tty, &rules, &dir, &a.cwd_rel).await {
            Decision::Interactive => {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "interactive",
                    "a terminal user is waiting on this command: run it where it was typed",
                ));
            }
            Decision::Local { reason, report } => local(reason, report),
            Decision::Heavy { row, tier } => {
                let Some(project) = a.project else {
                    return Ok(local("no_project", false));
                };
                let env = a
                    .env
                    .into_iter()
                    .filter(|(k, _)| crate::heavy::ENV_ALLOW.contains(&k.as_str()))
                    .collect();
                let start = Start {
                    project,
                    session: a.session,
                    terminal: a.terminal,
                    run_config: None,
                    argv: a.argv,
                    cwd_rel: a.cwd_rel,
                    env,
                    row,
                    tier: tier.as_str(),
                    secrets: Vec::new(),
                    // No secrets: nothing is leased, so no lease names a starter.
                    by: String::new(),
                    hosts: match a.net {
                        JobNet::Hosts(h) => Some(h),
                        JobNet::Registry | JobNet::Deny => None,
                    },
                };
                match run::start(app, start).await? {
                    Started::Local(why) => local(&why, true),
                    Started::Job { id, device_name } if from_runner => ndjson(&id, &device_name),
                    Started::Job { id, .. } => {
                        let row: Row =
                            sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE j.id = ?")))
                                .bind(&id)
                                .fetch_one(&app.pool)
                                .await?;
                        (StatusCode::CREATED, Json(Job::from(row))).into_response()
                    }
                }
            }
        },
    )
}

/// The 201 answer of `POST /runner/jobs`: the verdict line, then the job's frames, one JSON object
/// a line, until its `exit` (or its end with none: the shim then runs the command itself).
fn ndjson(id: &str, device_name: &str) -> Response {
    let Some(live) = run::get(id) else {
        return local("job_gone", false);
    };
    let verdict = json!({"verdict": "remote", "job": id, "device_name": device_name});
    let lines = run::lines(live, vec![format!("{verdict}\n")]);
    let body = axum::body::Body::from_stream(
        lines.map(|l| Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(l))),
    );
    Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/x-ndjson")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::JobNet;

    #[test]
    fn a_job_never_gets_more_network_than_the_sandbox_that_asked() {
        // E15 H2: `deny` (or an older runner that does not say) keeps the job local.
        assert_eq!(JobNet::of_sandbox(None, None), JobNet::Deny);
        assert_eq!(JobNet::of_sandbox(Some("deny"), None), JobNet::Deny);
        assert_eq!(JobNet::of_sandbox(Some("Allow"), None), JobNet::Deny);
        assert_eq!(JobNet::of_sandbox(Some("allow"), None), JobNet::Registry);
        // `filtered`: the session's list cut to the registry list; a forge never survives.
        let hosts = [
            "github.com",
            "CRATES.io",
            "evil.example",
            "pypi.org",
            "crates.io",
        ]
        .map(str::to_owned);
        assert_eq!(
            JobNet::of_sandbox(Some("filtered"), Some(&hosts[..])),
            JobNet::Hosts(vec!["crates.io".into(), "pypi.org".into()])
        );
        assert_eq!(
            JobNet::of_sandbox(Some("filtered"), None),
            JobNet::Hosts(Vec::new())
        );
        assert!(
            !ainkrad_proto::v2::JOB_REGISTRY_HOSTS
                .iter()
                .any(|h| h.contains("github"))
        );
    }
}
