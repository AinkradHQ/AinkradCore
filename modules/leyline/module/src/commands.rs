//! Pre-set commands (Y4-02): CRUD, and running one on a host through the gate.
//!
//! Security model.
//! - A command is data; running it is the gate's decision (`gate::authorize` with
//!   `Action::Preset(id)`): the gate reads the command's `read_only` flag and steps from this table
//!   itself and hashes them into what a person approves. A caller never says either.
//! - So a command that is flagged `read_only` is a grant to an AI on a read-only host: creating one,
//!   or changing the steps or the flag of one, needs a live step-up (an AI session never has one).
//!   Any other command can be edited freely: the gate treats it as a write anyway.
//! - `confirm` is a guard on the request (`confirm: true` must be sent), not a permission.
//! - Only a person writes commands: create, change and delete refuse an AI session outright.
//! - The scope says which hosts a command is for; the gate checks it (and hashes it) per host.
//! - Audit and event rows carry ids only, never a step's text.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller, step_up_required};
use ainkrad_core_server::store::{audit, begin_write, events};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::gate::{Action, Principal};
use crate::hosts::{In, elevated, find};
use crate::policy::Who;
use crate::valid;

const MAX_STEPS: usize = 20;
const MAX_STEP: usize = 1000;
const ROLES: &[&str] = &["production", "staging", "development", "other"];

/// A command as the gate reads it: what is hashed, approved and run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cmd {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) read_only: bool,
    pub(crate) confirm: bool,
    pub(crate) steps: Vec<String>,
    pub(crate) scope: Option<Scope>,
}

/// Unreadable stored steps are an error, never an empty list (an empty command would "succeed").
fn steps_of(raw: &str) -> Result<Vec<String>, sqlx::Error> {
    serde_json::from_str(raw).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

fn scope_of(r: &sqlx::sqlite::SqliteRow) -> Result<Option<Scope>, sqlx::Error> {
    let kind: String = r.try_get("scope_kind")?;
    if kind == "any" {
        return Ok(None);
    }
    Ok(Some(Scope {
        kind,
        value: r.try_get("scope_value")?,
        role: r.try_get("scope_role")?,
    }))
}

pub(crate) async fn load_cmd(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<Cmd>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT id, name, read_only, confirm, steps, scope_kind, scope_value, scope_role \
         FROM leyline_commands WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(Cmd {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        read_only: r.try_get::<i64, _>("read_only")? == 1,
        confirm: r.try_get::<i64, _>("confirm")? == 1,
        steps: steps_of(&r.try_get::<String, _>("steps")?)?,
        scope: scope_of(&r)?,
    }))
}

/// Which hosts a command is for.
#[derive(Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq, Debug)]
pub struct Scope {
    /// `host` (value: host id or label), `group`, `tag`, or `project` (value: the Core project's id,
    /// with an optional `role`).
    pub kind: String,
    pub value: String,
    /// With `project`: only hosts attached with this role.
    pub role: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CommandView {
    /// `lc_` and 16 hex characters.
    pub id: String,
    pub name: String,
    pub description: String,
    /// 1 to 20 command lines, run in order, stopping at the first failure.
    pub steps: Vec<String>,
    /// Absent = any host.
    pub scope: Option<Scope>,
    /// An AI may run it on a read-only host.
    pub read_only: bool,
    /// A run must be sent with `confirm: true`.
    pub confirm: bool,
    pub created_at: String,
    pub updated_at: String,
}

fn view(r: &sqlx::sqlite::SqliteRow) -> Result<CommandView, sqlx::Error> {
    let text = |c: &str| r.try_get::<String, _>(c);
    let scope = scope_of(r)?;
    Ok(CommandView {
        id: text("id")?,
        name: text("name")?,
        description: text("description")?,
        steps: steps_of(&text("steps")?)?,
        scope,
        read_only: r.try_get::<i64, _>("read_only")? == 1,
        confirm: r.try_get::<i64, _>("confirm")? == 1,
        created_at: text("created_at")?,
        updated_at: text("updated_at")?,
    })
}

#[derive(Deserialize, ToSchema)]
pub struct NewCommand {
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<String>,
    pub scope: Option<Scope>,
    pub read_only: Option<bool>,
    pub confirm: Option<bool>,
}

/// Every field is optional; `scope: null` clears the scope (any host).
#[derive(Deserialize, ToSchema)]
pub struct CommandPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub steps: Option<Vec<String>>,
    #[serde(default, deserialize_with = "some")]
    #[schema(value_type = Option<Scope>)]
    pub scope: Option<Option<Scope>>,
    pub read_only: Option<bool>,
    pub confirm: Option<bool>,
}

fn some<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Serialize, ToSchema)]
pub struct CommandDeleted {
    pub deleted: String,
}

/// Only a person writes commands: an AI session never creates, changes or removes one (a command
/// is a grant on read-only hosts, and its scope and steps decide where it runs).
fn people_only(me: &Caller) -> Result<(), ApiError> {
    if matches!(Principal::of(me).0, Who::Session(_)) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "gate_refused",
            "only a person may change pre-set commands",
        ));
    }
    Ok(())
}

fn bad() -> ApiError {
    ApiError::bad_request("the command is not valid")
}

/// A command as it will be written, already checked.
struct Fields {
    name: String,
    description: String,
    steps: Vec<String>,
    scope: Option<Scope>,
    read_only: bool,
    confirm: bool,
}

impl Fields {
    async fn check(&mut self, conn: &mut SqliteConnection) -> Result<(), ApiError> {
        let steps_ok = (1..=MAX_STEPS).contains(&self.steps.len())
            && self.steps.iter().all(|s| {
                !s.trim().is_empty() && s.chars().count() <= MAX_STEP && !s.contains('\0')
            });
        // A name that looks like an id could shadow one: refused.
        let id_like = self.name.trim().to_ascii_lowercase().starts_with("lc_");
        if !(valid::label(&self.name) && !id_like && steps_ok && self.description.chars().count() <= 500) {
            return Err(bad());
        }
        let Some(sc) = &mut self.scope else {
            return Ok(());
        };
        if sc.role.is_some()
            && (sc.kind != "project" || !ROLES.contains(&sc.role.as_deref().unwrap_or("")))
        {
            return Err(bad());
        }
        match sc.kind.as_str() {
            "host" => sc.value = find(conn, &sc.value).await?,
            "group" if valid::label(&sc.value) => {}
            "tag" if valid::tag(&sc.value) => sc.value.make_ascii_lowercase(),
            "project" => sc.value = crate::attach::project(conn, &sc.value).await?.0,
            _ => return Err(bad()),
        }
        Ok(())
    }
}

fn store_err(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            ApiError::conflict("a command with that name exists")
        }
        sqlx::Error::Database(d) if d.is_check_violation() => bad(),
        _ => e.into(),
    }
}

async fn record(conn: &mut SqliteConnection, op: &str, id: &str) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.command.{op}"),
        entity: None,
        details: json!({"command": id}).to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(conn, "leyline.command", &json!({"op": op, "id": id})).await?;
    Ok(())
}

/// The command `ident` names (id, else its unique name).
async fn find_cmd(conn: &mut SqliteConnection, ident: &str) -> Result<String, ApiError> {
    sqlx::query_scalar(
        "SELECT id FROM leyline_commands WHERE lower(id) = lower(?1) OR name = ?1 COLLATE NOCASE \
         ORDER BY lower(id) = lower(?1) DESC LIMIT 1",
    )
    .bind(ident.chars().take(256).collect::<String>())
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| ApiError::not_found("no such command"))
}

async fn load_view(conn: &mut SqliteConnection, id: &str) -> Result<CommandView, ApiError> {
    let row = sqlx::query("SELECT * FROM leyline_commands WHERE id = ?")
        .bind(id)
        .fetch_one(conn)
        .await?;
    Ok(view(&row)?)
}

async fn write(
    conn: &mut SqliteConnection,
    id: &str,
    f: &Fields,
    create: bool,
) -> Result<(), ApiError> {
    let (kind, value, role) = f.scope.as_ref().map_or(("any", None, None), |s| {
        (s.kind.as_str(), Some(&s.value), s.role.as_ref())
    });
    let sql = if create {
        "INSERT INTO leyline_commands (name, description, steps, scope_kind, scope_value, scope_role, read_only, confirm, id) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    } else {
        "UPDATE leyline_commands SET name = ?, description = ?, steps = ?, scope_kind = ?, scope_value = ?, \
         scope_role = ?, read_only = ?, confirm = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
    };
    sqlx::query(sql)
        .bind(&f.name)
        .bind(&f.description)
        .bind(json!(f.steps).to_string())
        .bind(kind)
        .bind(value)
        .bind(role)
        .bind(i64::from(f.read_only))
        .bind(i64::from(f.confirm))
        .bind(id)
        .execute(conn)
        .await
        .map_err(store_err)?;
    Ok(())
}

#[utoipa::path(get, path = "/commands", operation_id = "leylineListCommands", tag = "leyline",
    responses((status = 200, description = "Pre-set commands by name (at most 500)", body = Vec<CommandView>)))]
pub(crate) async fn list(State(app): State<App>) -> ApiResult<Vec<CommandView>> {
    let rows = sqlx::query("SELECT * FROM leyline_commands ORDER BY name COLLATE NOCASE LIMIT 500")
        .fetch_all(&app.pool)
        .await?;
    Ok(Json(rows.iter().map(view).collect::<Result<_, _>>()?))
}

#[utoipa::path(get, path = "/commands/{command}", operation_id = "leylineGetCommand", tag = "leyline",
    params(("command" = String, Path, description = "Command id, else its unique name")),
    responses((status = 200, description = "The command", body = CommandView)))]
pub(crate) async fn get(State(app): State<App>, Path(c): Path<String>) -> ApiResult<CommandView> {
    let mut conn = app.pool.acquire().await?;
    let id = find_cmd(&mut conn, &c).await?;
    Ok(Json(load_view(&mut conn, &id).await?))
}

#[utoipa::path(post, path = "/commands", operation_id = "leylineCreateCommand", tag = "leyline", request_body = NewCommand,
    responses((status = 200, description = "The new command (audited as `leyline.command.created`); a `read_only` one needs a step-up", body = CommandView)))]
pub(crate) async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    In(req): In<NewCommand>,
) -> ApiResult<CommandView> {
    people_only(&me)?;
    let mut f = Fields {
        name: req.name,
        description: req.description.unwrap_or_default(),
        steps: req.steps,
        scope: req.scope,
        read_only: req.read_only.unwrap_or(false),
        confirm: req.confirm.unwrap_or(false),
    };
    if f.read_only && !elevated(&app, &me) {
        return Err(step_up_required());
    }
    let mut tx = begin_write(&app.pool).await?;
    f.check(&mut tx).await?;
    let id = valid::new_id("lc_");
    write(&mut tx, &id, &f, true).await?;
    record(&mut tx, "created", &id).await?;
    let out = load_view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(patch, path = "/commands/{command}", operation_id = "leylinePatchCommand", tag = "leyline",
    params(("command" = String, Path, description = "Command id, else its unique name")), request_body = CommandPatch,
    responses((status = 200, description = "The changed command (audited as `leyline.command.changed`); changing the steps or the flag of a `read_only` one, or making one `read_only`, needs a step-up. A run already started keeps the steps it was decided with", body = CommandView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Path(c): Path<String>,
    Extension(me): Extension<Caller>,
    In(req): In<CommandPatch>,
) -> ApiResult<CommandView> {
    people_only(&me)?;
    let mut tx = begin_write(&app.pool).await?;
    let id = find_cmd(&mut tx, &c).await?;
    let cur = load_view(&mut tx, &id).await?;
    let (was_ro, was_steps, was_scope) = (cur.read_only, cur.steps.clone(), cur.scope.clone());
    let mut f = Fields {
        name: req.name.unwrap_or(cur.name),
        description: req.description.unwrap_or(cur.description),
        steps: req.steps.unwrap_or(cur.steps),
        scope: req.scope.unwrap_or(cur.scope),
        read_only: req.read_only.unwrap_or(cur.read_only),
        confirm: req.confirm.unwrap_or(cur.confirm),
    };
    f.check(&mut tx).await?;
    let widened = !was_ro || f.steps != was_steps || f.scope != was_scope;
    if f.read_only && widened && !elevated(&app, &me) {
        return Err(step_up_required());
    }
    write(&mut tx, &id, &f, false).await?;
    record(&mut tx, "changed", &id).await?;
    let out = load_view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/commands/{command}", operation_id = "leylineDeleteCommand", tag = "leyline",
    params(("command" = String, Path, description = "Command id, else its unique name")),
    responses((status = 200, description = "Deleted (audited as `leyline.command.deleted`); runs keep their results", body = CommandDeleted)))]
pub(crate) async fn remove(
    State(app): State<App>,
    Path(c): Path<String>,
    Extension(me): Extension<Caller>,
) -> ApiResult<CommandDeleted> {
    people_only(&me)?;
    let mut tx = begin_write(&app.pool).await?;
    let id = find_cmd(&mut tx, &c).await?;
    sqlx::query("DELETE FROM leyline_commands WHERE id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    record(&mut tx, "deleted", &id).await?;
    tx.commit().await?;
    Ok(Json(CommandDeleted { deleted: id }))
}

#[derive(Deserialize, ToSchema)]
pub struct RunRequest {
    /// Host id, else its unique label.
    pub host: String,
    /// Must be `true` when the command's `confirm` flag is set.
    pub confirm: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct RunStarted {
    /// The run's id (`lr_...`); read it with `GET /runs/{run}`.
    pub run: String,
    pub state: String,
}

#[utoipa::path(post, path = "/commands/{command}/run", operation_id = "leylineRunCommand", tag = "leyline",
    params(("command" = String, Path, description = "Command id, else its unique name")), request_body = RunRequest,
    responses((status = 200, description = "Past the gate: the steps run in the background, in order, stopping at the first failure; read the run for results. 403 `gate_refused` when the gate says no; 409 when the command is not for that host or needs `confirm`", body = RunStarted)))]
pub(crate) async fn run(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(c): Path<String>,
    In(req): In<RunRequest>,
) -> ApiResult<RunStarted> {
    let (cmd, host) = {
        let mut conn = app.pool.acquire().await?;
        let id = find_cmd(&mut conn, &c).await?;
        let cmd = load_view(&mut conn, &id).await?;
        let host = find(&mut conn, &req.host).await?;
        if cmd.confirm && req.confirm != Some(true) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "confirm_required",
                "this command must be confirmed: send confirm true",
            ));
        }
        (cmd, host)
    };
    let auth =
        crate::gate::authorize(&app, &Principal::of(&me), &host, &Action::Preset(cmd.id)).await?;
    let run = auth.run_id().to_owned();
    tokio::spawn(crate::exec::run(app.clone(), auth));
    Ok(Json(RunStarted {
        run,
        state: "running".to_owned(),
    }))
}

#[derive(Serialize, ToSchema)]
pub struct RunHost {
    pub host_id: String,
    /// `queued`, `needs_approval`, `ok`, `failed`, `refused` or `skipped`.
    pub state: String,
    /// The step the host got to (1-based).
    pub step: Option<i64>,
    /// The last step's exit code; absent when it was ended by a signal or did not run.
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    /// Each step's command line and output, redacted, at most 64 KB.
    pub output: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RunView {
    pub id: String,
    pub command_id: Option<String>,
    pub action: String,
    pub principal: String,
    /// `waiting_approval`, `running`, `done`, `cancelled` or `denied`.
    pub state: String,
    pub created_at: String,
    pub ended_at: Option<String>,
    pub hosts: Vec<RunHost>,
}

#[utoipa::path(get, path = "/runs/{run}", operation_id = "leylineGetRun", tag = "leyline",
    params(("run" = String, Path, description = "The run's id")),
    responses((status = 200, description = "The run and each host's result", body = RunView)))]
pub(crate) async fn get_run(State(app): State<App>, Path(id): Path<String>) -> ApiResult<RunView> {
    let id: String = id.chars().take(64).collect();
    let r = sqlx::query(
        "SELECT id, command_id, action, principal, state, created_at, ended_at FROM leyline_runs WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&app.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("no such run"))?;
    let rows = sqlx::query(
        "SELECT host_id, state, step, exit_code, duration_ms, output FROM leyline_run_hosts WHERE run_id = ? ORDER BY host_id",
    )
    .bind(&id)
    .fetch_all(&app.pool)
    .await?;
    let hosts = rows
        .iter()
        .map(|h| {
            Ok(RunHost {
                host_id: h.try_get("host_id")?,
                state: h.try_get("state")?,
                step: h.try_get("step")?,
                exit_code: h.try_get("exit_code")?,
                duration_ms: h.try_get("duration_ms")?,
                output: h.try_get("output")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    Ok(Json(RunView {
        id: r.try_get("id")?,
        command_id: r.try_get("command_id")?,
        action: r.try_get("action")?,
        principal: r.try_get("principal")?,
        state: r.try_get("state")?,
        created_at: r.try_get("created_at")?,
        ended_at: r.try_get("ended_at")?,
        hosts,
    }))
}
