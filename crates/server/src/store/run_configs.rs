//! Run configurations and environments (Core 0.10, E11-3; tables `core_run_configs`,
//! `core_run_envs`, `core_run_vars`). A configuration is a named way to run a project; at start
//! it is laid over one service of the project's run spec ([`overlay`]) together with the
//! variables of the chosen environment. SECURITY: a variable is a plain value or a reference to
//! one of the project's own secrets; a secret's value is never stored or read here, the runner
//! gets it through the same lease as for a `${secret:NAME}` in the spec. A plain value is
//! returned only by [`reveal`] (an `admin` route), never in a list. A plain value may not hold
//! `${`: it ends up in the spec, where that means a secret reference.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

use super::project_secrets;
use super::projects::{self, Who};
use super::run_specs::spec::{self, Port, RunSpec};
use super::secrets::Error;

/// The environments every project starts with.
pub const DEFAULT_ENVS: [&str; 2] = ["Development", "Staging"];
pub const MAX_CONFIGS: i64 = 32;
pub const MAX_ENVS: i64 = 8;
pub const MAX_VARS: i64 = 64;
pub const MAX_VALUE: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub command: String,
    pub workdir: String,
    /// `automatic`, or the id of a runner.
    pub runner: String,
    /// The service of the spec it is laid over; none picks one ([`target`]).
    pub service: Option<String>,
    pub port: Option<i64>,
    pub restart: bool,
    pub position: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// What a create or an update says; every field of an update is optional.
#[derive(Debug, Clone, Default)]
pub struct Input {
    pub name: Option<String>,
    pub command: Option<String>,
    pub workdir: Option<String>,
    pub runner: Option<String>,
    pub service: Option<String>,
    /// `Some(0)` clears the port.
    pub port: Option<i64>,
    pub restart: Option<bool>,
}

/// A variable of one configuration in one environment: exactly one of the two is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Var {
    pub key: String,
    pub value: Option<String>,
    /// The name of a project secret.
    pub secret: Option<String>,
}

/// How one key compares between two environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Same,
    Different,
    OnlyA,
    OnlyB,
}

impl Change {
    pub fn code(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Different => "different",
            Self::OnlyA => "only_a",
            Self::OnlyB => "only_b",
        }
    }
}

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

const COLS: &str = "id, project_id, name, command, workdir, runner, service, port, restart, \
                    position, created_at, updated_at";

fn config(r: &SqliteRow) -> Result<Config, sqlx::Error> {
    Ok(Config {
        id: r.try_get("id")?,
        project_id: r.try_get("project_id")?,
        name: r.try_get("name")?,
        command: r.try_get("command")?,
        workdir: r.try_get("workdir")?,
        runner: r.try_get("runner")?,
        service: r.try_get("service")?,
        port: r.try_get("port")?,
        restart: r.try_get::<i64, _>("restart")? != 0,
        position: r.try_get("position")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

// ---- pure helpers -------------------------------------------------------------------------

/// What is wrong with a variable name, if anything: `[A-Za-z_][A-Za-z0-9_]*`, at most 128.
pub fn key_problem(key: &str) -> Option<&'static str> {
    let b = key.as_bytes();
    let ok = (1..=128).contains(&b.len())
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    (!ok).then_some("a variable name is letters, digits and _, not starting with a digit")
}

/// What is wrong with a plain value, if anything.
pub fn value_problem(v: &str) -> Option<&'static str> {
    if v.len() > MAX_VALUE {
        return Some("a value is at most 8192 bytes");
    }
    if v.contains('\0') {
        return Some("a value cannot hold a NUL");
    }
    if v.contains("${") {
        return Some("a value cannot hold ${...}; link a Secret to use one");
    }
    None
}

fn line(text: &str, max: usize, what: &str) -> Result<(), Error> {
    match (1..=max).contains(&text.chars().count()) && !text.contains(['\n', '\r', '\0']) {
        true => Ok(()),
        false => refused(
            "bad_request",
            format!("{what} is 1-{max} characters on one line"),
        ),
    }
}

/// The result of reading a `.env` file: what was understood, and what was left out and why.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub vars: Vec<(String, String)>,
    /// `(line number, reason)` of each line that was not taken.
    pub skipped: Vec<(usize, String)>,
}

/// Reads `.env` text: `KEY=value` lines, an optional `export `, `#` comments and blank lines.
/// A value may be wrapped in matching single or double quotes (removed); an unquoted value ends
/// at ` #`. The last of two equal keys wins. Names and values are checked as a stored one is.
pub fn parse_dotenv(text: &str) -> Parsed {
    let mut out = Parsed::default();
    let mut at: BTreeMap<String, usize> = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").map_or(l, str::trim_start);
        let Some((k, v)) = l.split_once('=') else {
            out.skipped.push((n, "not KEY=value".to_owned()));
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        let v = match v.chars().next() {
            Some(q @ ('"' | '\'')) if v.len() >= 2 && v.ends_with(q) => &v[1..v.len() - 1],
            _ => v.split(" #").next().unwrap_or(v).trim_end(),
        };
        if let Some(why) = key_problem(k).or_else(|| value_problem(v)) {
            out.skipped.push((n, why.to_owned()));
            continue;
        }
        match at.get(k) {
            Some(&j) => out.vars[j] = (k.to_owned(), v.to_owned()),
            None => {
                at.insert(k.to_owned(), out.vars.len());
                out.vars.push((k.to_owned(), v.to_owned()));
            }
        }
    }
    out
}

/// Compares two environments of a configuration, by key (sorted); a secret and a plain value of
/// the same key differ, as do two secrets of different names. Plain values are compared, never
/// shown.
pub fn diff(a: &[Var], b: &[Var]) -> Vec<(String, Change)> {
    let ma: BTreeMap<&str, &Var> = a.iter().map(|v| (v.key.as_str(), v)).collect();
    let mb: BTreeMap<&str, &Var> = b.iter().map(|v| (v.key.as_str(), v)).collect();
    let keys: BTreeSet<&str> = ma.keys().chain(mb.keys()).copied().collect();
    keys.into_iter()
        .map(|k| {
            let c = match (ma.get(k), mb.get(k)) {
                (Some(x), Some(y)) if x.value == y.value && x.secret == y.secret => Change::Same,
                (Some(_), Some(_)) => Change::Different,
                (Some(_), None) => Change::OnlyA,
                _ => Change::OnlyB,
            };
            (k.to_owned(), c)
        })
        .collect()
}

/// The service a configuration is laid over: the one it names; else the first that mounts or
/// builds from a repo (it is the project's own code), else the first. `None` for no service.
pub fn target(spec: &RunSpec, cfg: &Config) -> Option<String> {
    if let Some(s) = cfg
        .service
        .as_ref()
        .filter(|s| spec.services.contains_key(*s))
    {
        return Some(s.clone());
    }
    spec.services
        .iter()
        .find(|(_, s)| s.repo.is_some() || s.build.is_some())
        .or_else(|| spec.services.iter().next())
        .map(|(n, _)| n.clone())
}

/// Lays `cfg` and its `vars` over the spec's [`target`] service: the command runs in the shell,
/// the folder (relative to the service's repo checkout unless absolute) and port are set, and
/// each variable becomes an environment entry (a secret as `${secret:NAME}`). The result is
/// checked as a saved spec is. The problem names what is wrong.
pub fn overlay(spec: &mut RunSpec, cfg: &Config, vars: &[Var]) -> Result<(), String> {
    let name = target(spec, cfg).ok_or("the project's run spec has no service")?;
    let s = spec.services.get_mut(&name).ok_or("no such service")?;
    s.command = Some(vec!["sh".into(), "-c".into(), cfg.command.clone()]);
    let dir = cfg.workdir.trim();
    if dir.starts_with('/') {
        s.workdir = Some(dir.to_owned());
    } else if let Some(repo) = &s.repo {
        let rel = dir.trim_start_matches("./").trim_matches('/');
        s.workdir = Some(match rel.is_empty() || rel == "." {
            true => format!("/repo/{repo}"),
            false => format!("/repo/{repo}/{rel}"),
        });
    }
    if let Some(p) = cfg.port.and_then(|p| u16::try_from(p).ok())
        && !s.ports.iter().any(|x| x.port == p)
    {
        s.ports.push(Port {
            port: p,
            expose: false,
        });
    }
    for v in vars {
        let val = match (&v.value, &v.secret) {
            (Some(x), None) => x.clone(),
            (None, Some(n)) => format!("${{secret:{n}}}"),
            _ => return Err(format!("{}: needs a value or a Secret", v.key)),
        };
        s.env.insert(v.key.clone(), val);
    }
    spec::validate(spec)
}

// ---- store ---------------------------------------------------------------------------------

/// The project's environments in order. A project that has none yet gets the defaults.
pub async fn environments(pool: &SqlitePool, project: i64) -> Result<Vec<String>, Error> {
    let q = "SELECT name FROM core_run_envs WHERE project_id = ? ORDER BY position, name";
    let have: Vec<String> = sqlx::query_scalar(q).bind(project).fetch_all(pool).await?;
    if !have.is_empty() {
        return Ok(have);
    }
    let mut tx = super::begin_write(pool).await?;
    projects::get(&mut tx, project).await?;
    for (i, n) in DEFAULT_ENVS.iter().enumerate() {
        sqlx::query(
            "INSERT OR IGNORE INTO core_run_envs (project_id, name, position) VALUES (?, ?, ?)",
        )
        .bind(project)
        .bind(n)
        .bind(i as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(sqlx::query_scalar(q).bind(project).fetch_all(pool).await?)
}

pub async fn add_environment(
    pool: &SqlitePool,
    project: i64,
    name: &str,
    who: Who<'_>,
) -> Result<Vec<String>, Error> {
    line(name, 40, "an environment name")?;
    let have = environments(pool, project).await?;
    if have.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        return refused("conflict", "the project already has that environment");
    }
    if have.len() as i64 >= MAX_ENVS {
        return refused("limit_reached", "a project has at most 8 environments");
    }
    let mut tx = super::begin_write(pool).await?;
    let p = projects::get(&mut tx, project).await?;
    if p.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    sqlx::query("INSERT INTO core_run_envs (project_id, name, position) VALUES (?, ?, ?)")
        .bind(project)
        .bind(name)
        .bind(have.len() as i64)
        .execute(&mut *tx)
        .await?;
    note(
        &mut tx,
        who,
        project,
        json!({"what": "environment_added", "name": name}),
    )
    .await?;
    tx.commit().await?;
    environments(pool, project).await
}

/// Removes an environment and every variable kept for it. The last one cannot go.
pub async fn delete_environment(
    pool: &SqlitePool,
    project: i64,
    name: &str,
    who: Who<'_>,
) -> Result<Vec<String>, Error> {
    let have = environments(pool, project).await?;
    if !have.iter().any(|n| n == name) {
        return refused("not_found", "no such environment");
    }
    if have.len() == 1 {
        return refused("conflict", "a project keeps at least one environment");
    }
    let mut tx = super::begin_write(pool).await?;
    sqlx::query(
        "DELETE FROM core_run_vars WHERE env = ? AND config_id IN \
         (SELECT id FROM core_run_configs WHERE project_id = ?)",
    )
    .bind(name)
    .bind(project)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM core_run_envs WHERE project_id = ? AND name = ?")
        .bind(project)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    note(
        &mut tx,
        who,
        project,
        json!({"what": "environment_deleted", "name": name}),
    )
    .await?;
    tx.commit().await?;
    environments(pool, project).await
}

/// One audit row (`project.updated`, no event); the details never hold a value.
async fn note(
    conn: &mut sqlx::SqliteConnection,
    who: Who<'_>,
    project: i64,
    mut details: serde_json::Value,
) -> Result<(), Error> {
    details["by_device"] = json!(who.by_device);
    projects::record(conn, who.actor, "project.updated", project, details, false).await
}

pub async fn list(pool: &SqlitePool, project: i64) -> Result<Vec<Config>, Error> {
    projects::get(&mut *pool.acquire().await?, project).await?;
    let q =
        format!("SELECT {COLS} FROM core_run_configs WHERE project_id = ? ORDER BY position, id");
    let rows = sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(project)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(config).collect::<Result<_, _>>()?)
}

pub async fn get(pool: &SqlitePool, project: i64, id: i64) -> Result<Config, Error> {
    let q = format!("SELECT {COLS} FROM core_run_configs WHERE id = ? AND project_id = ?");
    match sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(id)
        .bind(project)
        .fetch_optional(pool)
        .await?
    {
        Some(r) => Ok(config(&r)?),
        None => refused("not_found", "no such run configuration"),
    }
}

fn check(i: &Input) -> Result<(), Error> {
    if let Some(n) = &i.name {
        line(n, 60, "a name")?;
    }
    if let Some(c) = &i.command {
        line(c, 512, "a command")?;
    }
    if let Some(d) = &i.workdir
        && (d.len() > 200 || d.contains(['\n', '\r', '\0']) || d.split('/').any(|p| p == ".."))
    {
        return refused(
            "bad_request",
            "a folder is a path of at most 200 characters, without ..",
        );
    }
    if let Some(r) = &i.runner {
        line(r, 80, "a runner")?;
    }
    if let Some(s) = &i.service
        && !s.is_empty()
        && !spec::service_name_ok(s)
    {
        return refused("bad_request", "not a service name");
    }
    if let Some(p) = i.port
        && !(0..=65535).contains(&p)
    {
        return refused("bad_request", "a port is 1-65535");
    }
    Ok(())
}

pub async fn create(
    pool: &SqlitePool,
    project: i64,
    i: &Input,
    who: Who<'_>,
) -> Result<Config, Error> {
    check(i)?;
    let (Some(name), Some(command)) = (&i.name, &i.command) else {
        return refused("bad_request", "a configuration needs a name and a command");
    };
    let mut tx = super::begin_write(pool).await?;
    let p = projects::get(&mut tx, project).await?;
    if p.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_run_configs WHERE project_id = ?")
        .bind(project)
        .fetch_one(&mut *tx)
        .await?;
    if n >= MAX_CONFIGS {
        return refused(
            "limit_reached",
            "a project has at most 32 run configurations",
        );
    }
    let made = sqlx::query(
        "INSERT INTO core_run_configs (project_id, name, command, workdir, runner, service, port, \
         restart, position, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(project)
    .bind(name)
    .bind(command)
    .bind(i.workdir.as_deref().unwrap_or(""))
    .bind(i.runner.as_deref().unwrap_or("automatic"))
    .bind(i.service.as_deref().filter(|s| !s.is_empty()))
    .bind(i.port.filter(|p| *p > 0))
    .bind(i64::from(i.restart.unwrap_or(false)))
    .bind(n)
    .bind(who.now)
    .bind(who.now)
    .execute(&mut *tx)
    .await;
    let id = match made {
        Ok(r) => r.last_insert_rowid(),
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => {
            return refused(
                "conflict",
                "the project already has a configuration of that name",
            );
        }
        Err(e) => return Err(e.into()),
    };
    note(
        &mut tx,
        who,
        project,
        json!({"what": "run_config_created", "config": id}),
    )
    .await?;
    tx.commit().await?;
    get(pool, project, id).await
}

pub async fn update(
    pool: &SqlitePool,
    project: i64,
    id: i64,
    i: &Input,
    who: Who<'_>,
) -> Result<Config, Error> {
    check(i)?;
    let was = get(pool, project, id).await?;
    let mut tx = super::begin_write(pool).await?;
    let done = sqlx::query(
        "UPDATE core_run_configs SET name = ?, command = ?, workdir = ?, runner = ?, service = ?, \
         port = ?, restart = ?, updated_at = ? WHERE id = ? AND project_id = ?",
    )
    .bind(i.name.as_deref().unwrap_or(&was.name))
    .bind(i.command.as_deref().unwrap_or(&was.command))
    .bind(i.workdir.as_deref().unwrap_or(&was.workdir))
    .bind(i.runner.as_deref().unwrap_or(&was.runner))
    .bind(match &i.service {
        Some(s) => Some(s.as_str()).filter(|s| !s.is_empty()),
        None => was.service.as_deref(),
    })
    .bind(match i.port {
        Some(p) => Some(p).filter(|p| *p > 0),
        None => was.port,
    })
    .bind(i64::from(i.restart.unwrap_or(was.restart)))
    .bind(who.now)
    .bind(id)
    .bind(project)
    .execute(&mut *tx)
    .await;
    match done {
        Ok(_) => {}
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => {
            return refused(
                "conflict",
                "the project already has a configuration of that name",
            );
        }
        Err(e) => return Err(e.into()),
    }
    note(
        &mut tx,
        who,
        project,
        json!({"what": "run_config_updated", "config": id}),
    )
    .await?;
    tx.commit().await?;
    get(pool, project, id).await
}

pub async fn delete(pool: &SqlitePool, project: i64, id: i64, who: Who<'_>) -> Result<(), Error> {
    get(pool, project, id).await?;
    let mut tx = super::begin_write(pool).await?;
    sqlx::query("DELETE FROM core_run_vars WHERE config_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM core_run_configs WHERE id = ? AND project_id = ?")
        .bind(id)
        .bind(project)
        .execute(&mut *tx)
        .await?;
    note(
        &mut tx,
        who,
        project,
        json!({"what": "run_config_deleted", "config": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// A copy named `<name> copy` (then `copy 2`, ...), with every variable.
pub async fn duplicate(
    pool: &SqlitePool,
    project: i64,
    id: i64,
    who: Who<'_>,
) -> Result<Config, Error> {
    let was = get(pool, project, id).await?;
    let taken: Vec<String> = list(pool, project)
        .await?
        .into_iter()
        .map(|c| c.name)
        .collect();
    let mut name = format!("{} copy", was.name);
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("{} copy {n}", was.name);
        n += 1;
    }
    let copy = create(
        pool,
        project,
        &Input {
            name: Some(name),
            command: Some(was.command),
            workdir: Some(was.workdir),
            runner: Some(was.runner),
            service: was.service,
            port: was.port,
            restart: Some(was.restart),
        },
        who,
    )
    .await?;
    sqlx::query(
        "INSERT INTO core_run_vars (config_id, env, key, value, secret) \
         SELECT ?, env, key, value, secret FROM core_run_vars WHERE config_id = ?",
    )
    .bind(copy.id)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(copy)
}

/// The variables of a configuration in an environment, by key.
pub async fn vars(pool: &SqlitePool, config: i64, env: &str) -> Result<Vec<Var>, Error> {
    let rows = sqlx::query(
        "SELECT key, value, secret FROM core_run_vars WHERE config_id = ? AND env = ? ORDER BY key",
    )
    .bind(config)
    .bind(env)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            Ok(Var {
                key: r.try_get("key")?,
                value: r.try_get("value")?,
                secret: r.try_get("secret")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?)
}

async fn known_env(pool: &SqlitePool, project: i64, env: &str) -> Result<(), Error> {
    match environments(pool, project).await?.iter().any(|n| n == env) {
        true => Ok(()),
        false => refused("not_found", "no such environment"),
    }
}

#[allow(clippy::too_many_arguments)]
/// Sets (or replaces) one variable: a plain `value`, or a `secret` of the project. Exactly one.
pub async fn set_var(
    pool: &SqlitePool,
    project: i64,
    config: i64,
    env: &str,
    key: &str,
    value: Option<&str>,
    secret: Option<&str>,
    who: Who<'_>,
) -> Result<Var, Error> {
    get(pool, project, config).await?;
    known_env(pool, project, env).await?;
    if let Some(why) = key_problem(key) {
        return refused("bad_request", why);
    }
    match (value, secret) {
        (Some(v), None) => {
            if let Some(why) = value_problem(v) {
                return refused("bad_request", why);
            }
        }
        (None, Some(s)) => {
            let p = projects::get(&mut *pool.acquire().await?, project).await?;
            let want = BTreeSet::from([s.to_owned()]);
            project_secrets::check_refs(&mut *pool.acquire().await?, &p, &want).await?;
        }
        _ => return refused("bad_request", "give a value or a secret, not both"),
    }
    let mut tx = super::begin_write(pool).await?;
    let p = projects::get(&mut tx, project).await?;
    if p.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_run_vars WHERE config_id = ? AND env = ? AND key != ?",
    )
    .bind(config)
    .bind(env)
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    if n >= MAX_VARS {
        return refused("limit_reached", "an environment has at most 64 variables");
    }
    put(&mut tx, config, env, key, value, secret).await?;
    note(
        &mut tx,
        who,
        project,
        json!({"what": "run_var_set", "config": config, "env": env, "key": key,
               "secret": secret}),
    )
    .await?;
    tx.commit().await?;
    Ok(Var {
        key: key.to_owned(),
        value: value.map(str::to_owned),
        secret: secret.map(str::to_owned),
    })
}

async fn put(
    conn: &mut sqlx::SqliteConnection,
    config: i64,
    env: &str,
    key: &str,
    value: Option<&str>,
    secret: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO core_run_vars (config_id, env, key, value, secret) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT (config_id, env, key) DO UPDATE SET value = excluded.value, \
         secret = excluded.secret",
    )
    .bind(config)
    .bind(env)
    .bind(key)
    .bind(value)
    .bind(secret)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delete_var(
    pool: &SqlitePool,
    project: i64,
    config: i64,
    env: &str,
    key: &str,
    who: Who<'_>,
) -> Result<(), Error> {
    get(pool, project, config).await?;
    let mut tx = super::begin_write(pool).await?;
    let done = sqlx::query("DELETE FROM core_run_vars WHERE config_id = ? AND env = ? AND key = ?")
        .bind(config)
        .bind(env)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    if done.rows_affected() == 0 {
        return refused("not_found", "no such variable");
    }
    note(
        &mut tx,
        who,
        project,
        json!({"what": "run_var_deleted", "config": config, "env": env, "key": key}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// What an import did.
#[derive(Debug, PartialEq, Eq)]
pub struct Imported {
    pub imported: i64,
    pub skipped: Vec<(usize, String)>,
}

/// Reads `.env` text into an environment of a configuration (see [`parse_dotenv`]); a key already
/// there is replaced, even when it was a Secret link. All or nothing for the 64-variable cap.
pub async fn import(
    pool: &SqlitePool,
    project: i64,
    config: i64,
    env: &str,
    text: &str,
    who: Who<'_>,
) -> Result<Imported, Error> {
    get(pool, project, config).await?;
    known_env(pool, project, env).await?;
    let parsed = parse_dotenv(text);
    let mut tx = super::begin_write(pool).await?;
    let p = projects::get(&mut tx, project).await?;
    if p.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let have: Vec<String> =
        sqlx::query_scalar("SELECT key FROM core_run_vars WHERE config_id = ? AND env = ?")
            .bind(config)
            .bind(env)
            .fetch_all(&mut *tx)
            .await?;
    let new = parsed
        .vars
        .iter()
        .filter(|(k, _)| !have.contains(k))
        .count() as i64;
    if have.len() as i64 + new > MAX_VARS {
        return refused("limit_reached", "an environment has at most 64 variables");
    }
    for (k, v) in &parsed.vars {
        put(&mut tx, config, env, k, Some(v), None).await?;
    }
    note(
        &mut tx,
        who,
        project,
        json!({"what": "run_vars_imported", "config": config, "env": env,
               "count": parsed.vars.len()}),
    )
    .await?;
    tx.commit().await?;
    Ok(Imported {
        imported: parsed.vars.len() as i64,
        skipped: parsed.skipped,
    })
}

/// A plain value, for the Show button. A Secret link has none: 409 `conflict`.
pub async fn reveal(
    pool: &SqlitePool,
    project: i64,
    config: i64,
    env: &str,
    key: &str,
) -> Result<String, Error> {
    get(pool, project, config).await?;
    match vars(pool, config, env)
        .await?
        .into_iter()
        .find(|v| v.key == key)
    {
        None => refused("not_found", "no such variable"),
        Some(Var { value: Some(v), .. }) => Ok(v),
        Some(_) => refused(
            "conflict",
            "that variable comes from Secrets and has no shown value",
        ),
    }
}

#[cfg(test)]
mod tests;
