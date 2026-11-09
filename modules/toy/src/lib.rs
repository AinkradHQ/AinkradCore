//! The smallest complete module of the Core (E1-20.2): notes, three routes, one table. It is
//! the reference of `Docs/Specs/module-api-guide` and a fixture for the tests in `tests/`, which
//! drive it through the Core's real gate. Everything a module declares is here and small:
//! routes, migration, event kind, audit actions, scopes, the destructive list, a setting, a job.

use std::sync::{Arc, OnceLock};

use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Missed, Run, Schedule};
use ainkrad_core_server::module::{Module, ModuleSetting};
use ainkrad_core_server::store::modsettings::ModuleSettings;
use ainkrad_core_server::store::{Migration, audit, begin_write, events};
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, get};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{OpenApi, ToSchema};

pub const MODULE: &str = "toy";

pub static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "toy_0001",
    up: include_str!("../migrations/0001_toy_0001.up.sql"),
    down: include_str!("../migrations/0001_toy_0001.down.sql"),
}];

const SETTINGS: &[ModuleSetting] = &[ModuleSetting {
    name: "notes.max",
    default: 100,
    min: 1,
    max: 1000,
    description: "The most notes kept; the trim job deletes the oldest beyond it.",
}];

/// Declared once, used twice: `Module::destructive` and (below) the classification of every
/// other write. A write in neither list stops the Core at start.
const DESTRUCTIVE: &[(&str, &str)] = &[("DELETE", "/notes/{id}")];
const NON_DESTRUCTIVE: &[(&str, &str)] = &[("POST", "/notes")];
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[("GET", "/notes", "read")];

/// The module. `app` is filled by `attach`, so the job (which is handed no `App`) can work.
#[derive(Default, Clone)]
pub struct Toy {
    app: Arc<OnceLock<App>>,
}

#[derive(Serialize, ToSchema)]
pub struct Note {
    pub id: i64,
    pub title: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct NewNote {
    pub title: String,
    pub body: String,
}

#[derive(Serialize, ToSchema)]
pub struct Deleted {
    pub deleted: i64,
}

/// The most notes one list returns: a list is always bounded.
const PAGE: i64 = 200;

#[utoipa::path(get, path = "/notes", operation_id = "toyListNotes", tag = "toy",
    responses((status = 200, description = "The newest notes", body = Vec<Note>)))]
async fn list(State(app): State<App>) -> ApiResult<Vec<Note>> {
    let rows: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT id, title, body, created_at FROM toy_notes ORDER BY id DESC LIMIT ?",
    )
    .bind(PAGE)
    .fetch_all(&app.pool)
    .await?;
    let rows = rows
        .into_iter()
        .map(|(id, title, body, created_at)| Note {
            id,
            title,
            body,
            created_at,
        })
        .collect();
    Ok(Json(rows))
}

#[utoipa::path(post, path = "/notes", operation_id = "toyCreateNote", tag = "toy",
    request_body = NewNote,
    responses((status = 200, description = "The new note (audited as `toy.note.created`)", body = Note)))]
async fn create(State(app): State<App>, Json(n): Json<NewNote>) -> ApiResult<Note> {
    // Input is bounded here and by the table's CHECKs; the gate caps the request body itself.
    if n.title.trim().is_empty() || n.title.chars().count() > 100 || n.body.chars().count() > 4000 {
        return Err(ApiError::bad_request(
            "a title of 1 to 100 and a body of at most 4000 characters",
        ));
    }
    let max = ModuleSettings::of(&Toy::default())
        .get(&app.pool, "notes.max")
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let mut tx = begin_write(&app.pool).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM toy_notes")
        .fetch_one(&mut *tx)
        .await?;
    if count >= max {
        return Err(ApiError::conflict("the note limit is reached"));
    }
    let (id, created_at): (i64, String) = sqlx::query_as(
        "INSERT INTO toy_notes (title, body) VALUES (?, ?) RETURNING id, created_at",
    )
    .bind(&n.title)
    .bind(&n.body)
    .fetch_one(&mut *tx)
    .await?;
    record(&mut tx, "toy.note.created", id, "created").await?;
    tx.commit().await?;
    Ok(Json(Note {
        id,
        title: n.title,
        body: n.body,
        created_at,
    }))
}

#[utoipa::path(delete, path = "/notes/{id}", operation_id = "toyDeleteNote", tag = "toy",
    params(("id" = i64, Path, description = "Note id")),
    responses((status = 200, description = "Deleted (step-up; audited as `toy.note.deleted`)", body = Deleted)))]
async fn remove(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Deleted> {
    let mut tx = begin_write(&app.pool).await?;
    let gone = sqlx::query("DELETE FROM toy_notes WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if gone.rows_affected() == 0 {
        return Err(ApiError::not_found("no such note"));
    }
    record(&mut tx, "toy.note.deleted", id, "deleted").await?;
    tx.commit().await?;
    Ok(Json(Deleted { deleted: id }))
}

/// The audit row and the event of a change, in the change's own transaction. Names and ids
/// only: never the note's text (the audit chain cannot be pruned, and `details` is redacted
/// only for secret shapes).
async fn record(
    conn: &mut sqlx::SqliteConnection,
    action: &str,
    id: i64,
    op: &str,
) -> Result<(), sqlx::Error> {
    audit::append(
        conn,
        &NewAuditEvent {
            actor: BY,
            action: action.to_owned(),
            entity: Some(AuditEntity {
                kind: "note".to_owned(),
                id,
            }),
            details: "{}".to_owned(),
        },
    )
    .await?;
    events::append(conn, "toy.note", &json!({"op": op, "id": id})).await?;
    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    paths(list, create, remove),
    components(schemas(Note, NewNote, Deleted))
)]
struct Doc;

/// Keeps the newest `notes.max` notes: a lowered limit takes effect without a request.
struct Trim(Arc<OnceLock<App>>);

impl JobHandler for Trim {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = self.0.get().ok_or("the toy module is not attached")?;
            let max = ModuleSettings::of(&Toy::default())
                .get(&app.pool, "notes.max")
                .await
                .map_err(|e| e.to_string())?;
            let cut = sqlx::query(
                "DELETE FROM toy_notes WHERE id NOT IN (SELECT id FROM toy_notes ORDER BY id DESC LIMIT ?)",
            )
            .bind(max)
            .execute(&app.pool)
            .await
            .map_err(|e| e.to_string())?;
            if cut.rows_affected() == 0 {
                run.idle(); // nothing to do: no `job.ran` audit row for an idle poll
            }
            Ok(())
        })
    }
}

impl Module for Toy {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn routes(&self) -> Router<App> {
        Router::new()
            .route("/notes", get(list).post(create))
            .route("/notes/{id}", delete(remove))
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["toy.note"]
    }

    /// The event carries ids only, so a read-only device may see it.
    fn event_scope(&self, _kind: &str) -> &'static str {
        "read"
    }

    fn audit_actions(&self) -> &'static [&'static str] {
        &["toy.note.created", "toy.note.deleted"]
    }

    // Deny by default: a route not listed in `route_scopes` needs `admin`.
    fn scope(&self) -> &'static str {
        "admin"
    }

    fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        ROUTE_SCOPES
    }

    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        DESTRUCTIVE
    }

    fn non_destructive(&self) -> Option<&'static [(&'static str, &'static str)]> {
        Some(NON_DESTRUCTIVE)
    }

    fn openapi(&self) -> serde_json::Value {
        serde_json::to_value(Doc::openapi()).expect("the toy contract serialises")
    }

    fn settings(&self) -> &'static [ModuleSetting] {
        SETTINGS
    }

    fn jobs(&self) -> Vec<Job> {
        let job = Job::new(
            "trim",
            Schedule::Every(3600),
            Arc::new(Trim(self.app.clone())),
        );
        vec![Job {
            missed: Missed::Skip,
            ..job
        }]
    }

    fn attach(&self, app: &App) {
        let _ = self.app.set(app.clone());
    }
}
