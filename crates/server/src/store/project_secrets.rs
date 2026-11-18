//! Project secrets (Core 0.9, P4-04). SECURITY MODEL: a project's secrets are the members of its
//! own sealed-secret group `project-<slug>` (`core_projects.secret_group`); there is no second
//! store. Values go through `store::secrets` unchanged, so they are sealed at rest, gated by
//! `secrets.mode`, audited as `secret.*` and leave the Core only through a lease; nothing here
//! returns or logs one (there is no `Debug` on the value, and `ProjectSecret` has no value field).
//! A member is stored as `<slug>.<name>` (secret names are global), so two projects can both have
//! `db_password`, and a project cannot name another project's secret or a global one: the spec
//! sees only `<name>`. The prefix can never make an `acct.` provider-account name. The generic
//! `/secrets` routes refuse members of a `project-*` group, so the in-use check below cannot be
//! bypassed.
//!
//! CONTRACT for run-time `${secret:...}` resolution (the runner/lease path): resolve a name by
//! `core_secrets.group_id = project.secret_group` and `name = <slug>.<name>`, NEVER by the name
//! alone. Names are global, so a name lookup could reach another project's, a global or an
//! `acct.` secret. The generic `POST /secrets` also refuses `<existing-project-slug>.*`, so a
//! look-alike cannot be planted outside the group, but the group-id filter is the real guard.
//! An archived project refuses `set` only; `delete` still works so a leaked credential can be
//! revoked.

use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::projects::{self, Project, Who};
use super::run_specs::{RunSpec, spec};
use super::secret_groups;
use super::secrets::{self, ACCOUNT_PREFIX, Error, NewValue, valid_name};
use crate::ops::secretbox::SecretBox;

/// The group of every project's secrets is `project-<slug>`.
pub const GROUP_PREFIX: &str = "project-";

/// Whether `secret` is a member of a project's group: the generic `/secrets` routes leave those
/// to the project routes (the in-use check lives there).
pub async fn is_member(conn: &mut SqliteConnection, secret: &str) -> Result<bool, sqlx::Error> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_secrets s JOIN core_secret_groups g ON g.id = s.group_id \
         WHERE s.name = ? AND g.name GLOB 'project-*'",
    )
    .bind(secret)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// A project secret as listed: no value, ever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSecret {
    pub name: String,
    pub kind: String,
    pub description: String,
    pub version: i64,
    pub size: i64,
    pub updated_at: String,
    pub last_used_at: Option<String>,
    pub use_count: i64,
}

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

/// The stored name of `name` in project `slug`, or why it cannot be one.
fn stored(slug: &str, name: &str) -> Result<String, Error> {
    let full = format!("{slug}.{name}");
    if !valid_name(name) || !valid_name(&full) {
        return refused(
            "bad_request",
            "a secret name is [a-z][a-z0-9_.-]{0,63}, and with the project slug at most 64 characters",
        );
    }
    if full.starts_with(ACCOUNT_PREFIX) {
        return refused("bad_request", "that name is reserved for provider accounts");
    }
    Ok(full)
}

/// The project's secret group, made (and linked) the first time it is needed; projects made
/// before this story get theirs lazily. Inside the caller's write transaction.
pub async fn ensure_group(
    conn: &mut SqliteConnection,
    project: &Project,
    who: Who<'_>,
) -> Result<i64, Error> {
    if let Some(id) = project.secret_group {
        return Ok(id);
    }
    let name = format!("{GROUP_PREFIX}{}", project.slug);
    let g = secret_groups::create_in(
        conn,
        &name,
        &format!("Secrets of project {}", project.slug),
        &[],
        who.by_device,
        who.actor,
        who.now,
    )
    .await?;
    sqlx::query("UPDATE core_projects SET secret_group = ? WHERE id = ?")
        .bind(g.id)
        .bind(project.id)
        .execute(&mut *conn)
        .await?;
    Ok(g.id)
}

/// The names (without the slug prefix) of the project's secrets.
pub async fn names(conn: &mut SqliteConnection, project: &Project) -> Result<Vec<String>, Error> {
    let Some(group) = project.secret_group else {
        return Ok(Vec::new());
    };
    let prefix = format!("{}.", project.slug);
    let all: Vec<String> =
        sqlx::query_scalar("SELECT name FROM core_secrets WHERE group_id = ? ORDER BY name")
            .bind(group)
            .fetch_all(&mut *conn)
            .await?;
    Ok(all
        .into_iter()
        .filter_map(|n| n.strip_prefix(&prefix).map(str::to_owned))
        .collect())
}

/// Every secret of the project, by name; never a value.
pub async fn list(pool: &SqlitePool, project_id: i64) -> Result<Vec<ProjectSecret>, Error> {
    let project = projects::get(&mut *pool.acquire().await?, project_id).await?;
    if project.secret_group.is_none() {
        return Ok(Vec::new());
    }
    let prefix = format!("{}.", project.slug);
    // Members by group id, the same filter as `names`, `check_refs` and `delete`.
    let members = names(&mut *pool.acquire().await?, &project).await?;
    let mut out = Vec::new();
    for m in secrets::list(pool).await? {
        if let Some(name) = m
            .name
            .strip_prefix(&prefix)
            .filter(|n| members.iter().any(|x| x == n))
        {
            out.push(ProjectSecret {
                name: name.to_owned(),
                kind: m.kind,
                description: m.description,
                version: m.version,
                size: m.size,
                updated_at: m.updated_at,
                last_used_at: m.last_used_at,
                use_count: m.use_count,
            });
        }
    }
    Ok(out)
}

/// What a write carries: the value (write-only) and how to read it.
pub struct Input<'a> {
    pub value: &'a str,
    pub kind: Option<&'a str>,
    pub description: Option<&'a str>,
    pub file_name: Option<&'a str>,
    pub file_mode: Option<i64>,
}

/// Stores `name` for the project (a new secret) or rotates it (a new version). The broker's own
/// gates apply: `secrets.mode`, value shape, size, count. Refused for an archived project.
pub async fn set(
    pool: &SqlitePool,
    sealer: &SecretBox,
    project_id: i64,
    name: &str,
    input: &Input<'_>,
    who: Who<'_>,
) -> Result<ProjectSecret, Error> {
    let mut tx = super::begin_write(pool).await?;
    let project = projects::get(&mut tx, project_id).await?;
    if project.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let full = stored(&project.slug, name)?;
    ensure_group(&mut tx, &project, who).await?;
    let group = format!("{GROUP_PREFIX}{}", project.slug);
    let new = NewValue {
        value: input.value,
        kind: input.kind,
        description: input.description,
        file_name: input.file_name,
        file_mode: input.file_mode,
        group: Some(&group),
        ..NewValue::default()
    };
    let have = sqlx::query_scalar::<_, Option<String>>(
        "SELECT g.name FROM core_secrets s LEFT JOIN core_secret_groups g ON g.id = s.group_id \
         WHERE s.name = ?",
    )
    .bind(&full)
    .fetch_optional(&mut *tx)
    .await?
    .map(Option::unwrap_or_default);
    match have {
        None => {
            secrets::create_in(
                &mut tx,
                sealer,
                &full,
                &new,
                who.by_device,
                who.actor,
                who.now,
            )
            .await?
        }
        Some(g) if g == group => {
            secrets::rotate_in(
                &mut tx,
                sealer,
                &full,
                &new,
                who.by_device,
                who.actor,
                who.now,
            )
            .await?
        }
        Some(_) => {
            return refused(
                "conflict",
                "a secret of that name exists outside the project",
            );
        }
    };
    tx.commit().await?;
    list(pool, project_id)
        .await?
        .into_iter()
        .find(|s| s.name == name)
        .ok_or(Error::Db(sqlx::Error::RowNotFound))
}

/// The spec versions that refer to `${secret:name}`, newest first.
async fn used_by(
    conn: &mut SqliteConnection,
    project_id: i64,
    name: &str,
) -> Result<Vec<i64>, Error> {
    let rows = sqlx::query(
        "SELECT version, spec FROM core_project_run_specs WHERE project_id = ? \
         ORDER BY version DESC",
    )
    .bind(project_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::new();
    for r in rows {
        let text: String = r.try_get("spec")?;
        let uses = serde_json::from_str::<RunSpec>(&text)
            .is_ok_and(|s| spec::secret_refs(&s).contains(name));
        if uses {
            out.push(r.try_get("version")?);
        }
    }
    Ok(out)
}

/// Deletes the project's secret `name` (and its leases), also for an archived project. A secret that a spec version refers to
/// is a 409 `conflict` naming the newest such version, unless `force`; the specs are never
/// changed, so a forced delete leaves them referring to a secret that is gone until they are
/// saved again.
pub async fn delete(
    pool: &SqlitePool,
    project_id: i64,
    name: &str,
    force: bool,
    who: Who<'_>,
) -> Result<(), Error> {
    let mut tx = super::begin_write(pool).await?;
    // Allowed while archived: a leaked credential must stay revocable.
    let project = projects::get(&mut tx, project_id).await?;
    if !names(&mut tx, &project).await?.iter().any(|n| n == name) {
        return refused("not_found", "no such project secret");
    }
    let used = used_by(&mut tx, project_id, name).await?;
    if let (Some(newest), false) = (used.first(), force) {
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT max(version) FROM core_project_run_specs WHERE project_id = ?",
        )
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await?;
        let which = match current == Some(*newest) {
            true => format!("spec version {newest}, the current one"),
            false => format!("spec version {newest}"),
        };
        let more = match used.len() {
            1 => String::new(),
            n => format!(" (and {} older)", n - 1),
        };
        return refused(
            "conflict",
            format!(
                "secret {name} is used by {which}{more}; delete it again with force=true to remove it anyway"
            ),
        );
    }
    secrets::delete_in(
        &mut tx,
        &stored(&project.slug, name)?,
        who.by_device,
        who.actor,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The spec check (`run_specs::save`): every name must be one of the project's secrets.
pub async fn check_refs(
    conn: &mut SqliteConnection,
    project: &Project,
    wanted: &std::collections::BTreeSet<String>,
) -> Result<(), Error> {
    if wanted.is_empty() {
        return Ok(());
    }
    let have = names(conn, project).await?;
    for n in wanted {
        if !have.contains(n) {
            return refused(
                "invalid_spec",
                format!(
                    "${{secret:{n}}} is not a secret of this project; add it under project secrets first"
                ),
            );
        }
    }
    Ok(())
}

/// Test fixtures: a throwaway value, a device to own it.
#[cfg(test)]
pub(crate) mod fixtures {
    use ainkrad_core::audit::AuditActor;
    use ainkrad_core::settings::{Key, Scope};

    use super::*;

    pub const VALUE: &str = "throwaway-project-value-3c9e41";
    pub const DEVICE: &str = "d_aaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub const NOW: &str = "2026-11-17T10:00:00.000Z";

    /// Broker on (mode 1) and a master key; the device row a secret's owner needs.
    pub async fn broker(pool: &SqlitePool) -> SecretBox {
        crate::store::settings::set(
            pool,
            Key::SecretsMode,
            Scope::Server,
            "1",
            AuditActor::System,
            NOW,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO core_devices (id, kind, name, routine_spki, fingerprint, \
             status) VALUES (?, 'device', 'seed', zeroblob(91), ?, 'active')",
        )
        .bind(DEVICE)
        .bind("a".repeat(43))
        .execute(pool)
        .await
        .unwrap();
        SecretBox::new(&[7; 32])
    }

    pub fn who() -> Who<'static> {
        Who {
            by_device: DEVICE,
            actor: AuditActor::System,
            now: NOW,
        }
    }

    /// Stores each of `names` as a project secret with [`VALUE`].
    pub async fn seed(pool: &SqlitePool, project: i64, names: &[&str]) {
        let sealer = broker(pool).await;
        for n in names {
            let input = Input {
                value: VALUE,
                kind: None,
                description: None,
                file_name: None,
                file_mode: None,
            };
            set(pool, &sealer, project, n, &input, who()).await.unwrap();
        }
    }
}

#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod tests;
