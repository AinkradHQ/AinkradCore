//! A `task` run configuration (E15-3): `POST …/run-configs/{id}/run` starts it as a heavy job
//! (`heavy::run`) instead of a `run.start` service. The answer is still a [`ProjectRun`], with the
//! job's id in `job`; the job's own routes (`/jobs/{id}`, its stream) follow it from there.

use axum::http::StatusCode;

use super::super::types::ts;
use super::super::{ApiError, Caller};
use super::runs::ProjectRun;
use crate::api::App;
use crate::heavy::rules::{self, Row, Verdict};
use crate::heavy::run::{self, Start, Started};
use crate::runs::project_secret;
use crate::store::projects;
use crate::store::run_configs::{self as store, Config};

/// The folder a task's `workdir` names, relative to the project (`""` is its root). An absolute
/// one, or one that leaves the project, is refused: a task runs in the workspace, not a container.
fn cwd_of(workdir: &str) -> Result<String, ApiError> {
    let rel = workdir.trim().trim_start_matches("./").trim_matches('/');
    let rel = if rel == "." { "" } else { rel };
    if workdir.trim().starts_with('/')
        || (!rel.is_empty() && ainkrad_proto::v2::synctree::check_path(rel).is_err())
    {
        return Err(ApiError::bad_request(
            "a task's folder is a path inside the project",
        ));
    }
    Ok(rel.to_owned())
}

/// What the command needs, from the rules of its first words (`cargo test` …); a command no rule
/// knows is heavy with no toolchain need: the user chose to run it as a task.
fn row_of(command: &str, project_rules: &[rules::ProjectRule]) -> Row {
    let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
    match rules::decide(&words, false, project_rules) {
        Verdict::Rule(row, _) => row,
        _ => Row {
            heavy: true,
            ..Row::default()
        },
    }
}

pub(super) async fn start(
    app: &App,
    me: &Caller,
    project_id: i64,
    cfg: &Config,
    environment: Option<String>,
) -> Result<ProjectRun, ApiError> {
    let project = projects::get(&mut *app.pool.acquire().await?, project_id).await?;
    if project.state == "archived" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "the project is archived",
        ));
    }
    let envs = store::environments(&app.pool, project_id).await?;
    let env_name = match environment {
        Some(e) if envs.contains(&e) => e,
        Some(_) => return Err(ApiError::not_found("no such environment")),
        None => envs.first().cloned().unwrap_or_default(),
    };
    let mut env = std::collections::BTreeMap::new();
    let mut secrets = Vec::new();
    for v in store::vars(&app.pool, cfg.id, &env_name).await? {
        match (v.value, v.secret) {
            (Some(x), None) => {
                env.insert(v.key, x);
            }
            (None, Some(name)) => {
                let stored = project_secret(&app.pool, &project, &name)
                    .await
                    .map_err(|why| ApiError::new(StatusCode::CONFLICT, "invalid_spec", why))?;
                secrets.push((v.key, stored));
            }
            _ => {
                return Err(ApiError::bad_request(
                    "a variable needs a value or a Secret",
                ));
            }
        }
    }
    let ws = crate::heavy::workspace();
    let toml = tokio::fs::read_to_string(ws.jobs_toml(project_id))
        .await
        .unwrap_or_default();
    let s = Start {
        project: project_id,
        session: None,
        terminal: None,
        run_config: Some(cfg.id),
        argv: vec!["sh".into(), "-c".into(), cfg.command.clone()],
        cwd_rel: cwd_of(&cfg.workdir)?,
        env,
        row: row_of(&cfg.command, &rules::parse_project(&toml)),
        tier: "config",
        secrets,
        by: me.device.id.clone(),
    };
    let now = app.clock.now();
    match run::start(app, s).await? {
        Started::Job { id, .. } => {
            let device: String =
                sqlx::query_scalar("SELECT device_id FROM core_hw_jobs WHERE id = ?")
                    .bind(&id)
                    .fetch_one(&app.pool)
                    .await?;
            Ok(ProjectRun {
                id: id.clone(),
                spec_version: 0,
                runner: device,
                state: "starting".to_owned(),
                stop_reason: None,
                error: None,
                started_by: me.device.id.clone(),
                started_at: ts(&now),
                stopped_at: None,
                last_activity_at: None,
                idle_stop_at: None,
                config_id: Some(cfg.id),
                environment: Some(env_name),
                job: Some(id),
            })
        }
        Started::Local(why) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "no_runner",
            format!("no hardware can run the task ({why})"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tasks_folder_stays_inside_the_project() {
        assert_eq!(cwd_of("").unwrap(), "");
        assert_eq!(cwd_of(".").unwrap(), "");
        assert_eq!(cwd_of("./web/").unwrap(), "web");
        assert!(cwd_of("/srv").is_err());
        assert!(cwd_of("../x").is_err());
        assert!(cwd_of("a/.git/x").is_err());
    }

    #[test]
    fn an_unknown_tasks_command_is_heavy() {
        assert!(row_of("./scripts/build.sh --all", &[]).heavy);
        assert!(row_of("cargo test", &[]).heavy);
    }
}
