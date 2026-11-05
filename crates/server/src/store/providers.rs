//! Provider definitions (KAN-429; design `2026-11-02-ai-provider-accounts` §4, §11b item 1): what
//! an AI provider is, as data. The three built-ins (`anthropic`, `openai`, `google`) are code and
//! cannot be edited. A user definition is a row, validated before it is stored:
//!
//! - the base URL is `https://`, a DNS host name (no IP literal, no `localhost`, no credentials,
//!   query or fragment), because the auth gateway will connect to it with a key;
//! - the authentication variable is one of its harness's own ([`ainkrad_proto::v2::account_vars`]),
//!   never a proxy, base-URL, endpoint or certificate variable: the same rule the broker and the
//!   runner apply to a session, so a definition can never name a variable they would refuse;
//! - model ids, prices, delivery methods and the usage parser are from closed, bounded sets.
//!
//! Editing a definition needs a step-up (the caller's route, KAN-432). Core never connects to a
//! definition's URL itself (no probe). An account is bound to its provider's base URL when it is
//! stored (`core_accounts.base_url`), so an edit afterwards cannot move a stored key.
//!
//! A user definition holds accounts when it declares a `key_prefix` and is delivered through the
//! gateway only (KAN-435 G7, design §5.3): the broker binds each of its keys to the definition's
//! host (`provider_rules`, `secrets_user`). `wire` is the dialect the gateway speaks to it.

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_proto::v2::{account_vars, redirects_traffic, valid_secret_var};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::provider_rules::{self as rules, wire_for};
use super::secrets::Error;

/// How a key reaches a session: a leased environment variable, or the auth gateway (KAN-435).
pub const DELIVERY: [&str; 2] = ["env", "gateway"];
/// How an account is signed in: a pasted key. (Device-code and browser sign-ins are not built.)
pub const LOGIN: [&str; 1] = ["paste"];
/// The usage decoders a definition may name.
pub const USAGE_PARSERS: [&str; 4] = ["anthropic", "openai", "google", "none"];
const MAX_USER_DEFS: i64 = 32;
const MAX_MODELS: usize = 64;
/// A price of more than this many micro-dollars per million tokens is a typo, not a price.
const MAX_PRICE: i64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Model {
    pub id: String,
    /// List price per million input tokens, in millionths of a dollar.
    pub input_per_mtok_micro: i64,
    pub output_per_mtok_micro: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Definition {
    pub id: String,
    pub name: String,
    pub harness: String,
    pub auth_var: String,
    pub base_url: String,
    pub usage_parser: String,
    pub delivery: Vec<String>,
    pub login_methods: Vec<String>,
    pub models: Vec<Model>,
    /// When the models' list prices were read; the screen shows it (prices go stale).
    pub priced_at: Option<String>,
    /// The API dialect the gateway speaks to this provider (`provider_rules::WIRES`); empty reads
    /// as the harness's own.
    #[serde(default)]
    pub wire: String,
    /// The shape this provider's keys start with, so the broker can bind a key to this
    /// definition's host (design §5.3). A user definition only; it makes the definition
    /// gateway-only.
    #[serde(default)]
    pub key_prefix: Option<String>,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default)]
    pub version: i64,
}

fn builtin(id: &str, name: &str, harness: &str, var: &str, url: &str, parser: &str) -> Definition {
    Definition {
        id: id.to_owned(),
        name: name.to_owned(),
        harness: harness.to_owned(),
        auth_var: var.to_owned(),
        base_url: url.to_owned(),
        usage_parser: parser.to_owned(),
        // An API key reaches a session only through the gateway (design §10 Q4).
        delivery: vec!["gateway".to_owned()],
        login_methods: vec!["paste".to_owned()],
        // Prices are the cost ledger's (KAN-449); none are invented here.
        models: Vec::new(),
        priced_at: None,
        wire: wire_for(harness).to_owned(),
        key_prefix: None,
        builtin: true,
        version: 1,
    }
}

/// The built-in providers, in code.
pub fn built_in() -> Vec<Definition> {
    vec![
        builtin(
            "anthropic",
            "Anthropic",
            "claude",
            "ANTHROPIC_API_KEY",
            "https://api.anthropic.com",
            "anthropic",
        ),
        builtin(
            "openai",
            "OpenAI",
            "codex",
            "OPENAI_API_KEY",
            "https://api.openai.com/v1",
            "openai",
        ),
        builtin(
            "google",
            "Google Gemini",
            "agy",
            "GEMINI_API_KEY",
            "https://generativelanguage.googleapis.com",
            "google",
        ),
    ]
}

fn bad<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code: "bad_request",
        message: message.into(),
    })
}

pub use super::provider_url::url_problem;

/// Why `d` is not an acceptable user definition, if it is not.
pub fn problem(d: &Definition) -> Option<String> {
    let id_ok = (1..=32).contains(&d.id.len())
        && d.id.as_bytes()[0].is_ascii_lowercase()
        && d.id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !id_ok {
        return Some("an id is [a-z][a-z0-9-]{0,31}".to_owned());
    }
    if built_in().iter().any(|b| b.id == d.id) {
        return Some("that id is a built-in provider".to_owned());
    }
    if !(1..=64).contains(&d.name.len()) || d.name.chars().any(char::is_control) {
        return Some("a name is 1 to 64 printable characters".to_owned());
    }
    let vars = account_vars(&d.harness);
    if vars.is_empty() {
        return Some("harness is claude, codex or agy".to_owned());
    }
    if !valid_secret_var(&d.auth_var)
        || redirects_traffic(&d.auth_var)
        || !vars.contains(&d.auth_var.as_str())
    {
        return Some(format!(
            "auth_var must be one of {} 's own authentication variables: {}",
            d.harness,
            vars.join(", ")
        ));
    }
    if let Some(why) = url_problem(&d.base_url) {
        return Some(why.to_owned());
    }
    if let Some(why) = rules::problem(d) {
        return Some(why);
    }
    if !USAGE_PARSERS.contains(&d.usage_parser.as_str()) {
        return Some(format!(
            "usage_parser is one of {}",
            USAGE_PARSERS.join(", ")
        ));
    }
    if d.delivery.is_empty() || d.delivery.iter().any(|m| !DELIVERY.contains(&m.as_str())) {
        return Some(format!(
            "delivery is a non-empty list of {}",
            DELIVERY.join(", ")
        ));
    }
    if d.login_methods.is_empty() || d.login_methods.iter().any(|m| !LOGIN.contains(&m.as_str())) {
        return Some(format!(
            "login_methods is a non-empty list of {}",
            LOGIN.join(", ")
        ));
    }
    if d.models.len() > MAX_MODELS {
        return Some(format!("at most {MAX_MODELS} models"));
    }
    for (i, m) in d.models.iter().enumerate() {
        let id_ok = (1..=80).contains(&m.id.len())
            && m.id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b));
        if !id_ok || d.models[..i].iter().any(|o| o.id == m.id) {
            return Some(
                "a model id is 1 to 80 of [A-Za-z0-9._:/-], once, exactly as the provider \
                 names it: the gateway grants and compares these ids as they are and resolves no alias"
                    .to_owned(),
            );
        }
        if let Some(why) = rules::model_problem(&m.id) {
            return Some(why.to_owned());
        }
        let price_ok = |p: i64| (0..=MAX_PRICE).contains(&p);
        if !price_ok(m.input_per_mtok_micro) || !price_ok(m.output_per_mtok_micro) {
            return Some(format!(
                "a price is 0 to {MAX_PRICE} micro-dollars per million tokens"
            ));
        }
    }
    if d.priced_at
        .as_deref()
        .is_some_and(|t| t.len() > 40 || t.chars().any(char::is_control))
    {
        return Some("priced_at is a short timestamp".to_owned());
    }
    None
}

fn row(r: SqliteRow) -> Result<Definition, sqlx::Error> {
    let js = |c: &str| -> Result<String, sqlx::Error> { r.try_get(c) };
    Ok(Definition {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        harness: r.try_get("harness")?,
        auth_var: r.try_get("auth_var")?,
        base_url: r.try_get("base_url")?,
        usage_parser: r.try_get("usage_parser")?,
        delivery: serde_json::from_str(&js("delivery")?).unwrap_or_default(),
        login_methods: serde_json::from_str(&js("login_methods")?).unwrap_or_default(),
        models: serde_json::from_str(&js("models")?).unwrap_or_default(),
        priced_at: r.try_get("priced_at")?,
        wire: r.try_get("wire")?,
        key_prefix: r.try_get("key_prefix")?,
        builtin: false,
        version: r.try_get("version")?,
    })
}

const COLUMNS: &str = "id, name, harness, auth_var, base_url, usage_parser, delivery, \
    login_methods, models, priced_at, version, wire, key_prefix";

/// Every provider: the built-ins, then the user definitions by id.
pub async fn list(pool: &SqlitePool) -> Result<Vec<Definition>, sqlx::Error> {
    let sql = format!("SELECT {COLUMNS} FROM core_provider_defs ORDER BY id");
    let mut all = built_in();
    for r in sqlx::query(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await?
    {
        all.push(row(r)?);
    }
    Ok(all)
}

/// One provider by id, a built-in or a user definition.
pub async fn get_in(conn: &mut SqliteConnection, id: &str) -> Result<Definition, Error> {
    if let Some(b) = built_in().into_iter().find(|b| b.id == id) {
        return Ok(b);
    }
    let sql = format!("SELECT {COLUMNS} FROM core_provider_defs WHERE id = ?");
    match sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
    {
        Some(r) => Ok(row(r)?),
        None => Err(Error::Refused {
            code: "not_found",
            message: "no such provider".to_owned(),
        }),
    }
}

pub async fn get(pool: &SqlitePool, id: &str) -> Result<Definition, Error> {
    let mut conn = pool.acquire().await?;
    get_in(&mut conn, id).await
}

async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    d: &Definition,
    by_device: &str,
) -> Result<(), Error> {
    // The URL and the variable name are not secrets; a definition holds no key.
    let details = json!({"id": d.id, "harness": d.harness, "auth_var": d.auth_var,
                         "base_url": d.base_url, "models": d.models.len(),
                         "version": d.version, "by_device": by_device});
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: None,
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

async fn write(
    conn: &mut SqliteConnection,
    d: &Definition,
    insert: bool,
    now: &str,
) -> Result<(), sqlx::Error> {
    let sql = match insert {
        true => {
            "INSERT INTO core_provider_defs (id, name, harness, auth_var, base_url, \
                 usage_parser, delivery, login_methods, models, priced_at, version, created_at, \
                 updated_at, wire, key_prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        }
        false => {
            "UPDATE core_provider_defs SET name = ?2, harness = ?3, auth_var = ?4, \
                  base_url = ?5, usage_parser = ?6, delivery = ?7, login_methods = ?8, \
                  models = ?9, priced_at = ?10, version = ?11, updated_at = ?13, wire = ?14, \
                  key_prefix = ?15 WHERE id = ?1"
        }
    };
    sqlx::query(sql)
        .bind(&d.id)
        .bind(&d.name)
        .bind(&d.harness)
        .bind(&d.auth_var)
        .bind(&d.base_url)
        .bind(&d.usage_parser)
        .bind(json!(d.delivery).to_string())
        .bind(json!(d.login_methods).to_string())
        .bind(json!(d.models).to_string())
        .bind(&d.priced_at)
        .bind(d.version)
        .bind(now)
        .bind(now)
        .bind(&d.wire)
        .bind(&d.key_prefix)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Stores a new user definition.
pub async fn create(
    pool: &SqlitePool,
    d: &Definition,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Definition, Error> {
    if let Some(why) = problem(d) {
        return bad(why);
    }
    let mut d = d.clone();
    (d.builtin, d.version) = (false, 1);
    if d.wire.is_empty() {
        d.wire = wire_for(&d.harness).to_owned();
    }
    let mut tx = super::begin_write(pool).await?;
    if let Some(why) = rules::prefix_conflict(&mut tx, &d).await? {
        return bad(why);
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_provider_defs")
        .fetch_one(&mut *tx)
        .await?;
    if n >= MAX_USER_DEFS {
        return Err(Error::Refused {
            code: "limit_reached",
            message: format!("at most {MAX_USER_DEFS} user definitions"),
        });
    }
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_provider_defs WHERE id = ?")
        .bind(&d.id)
        .fetch_one(&mut *tx)
        .await?;
    if taken > 0 {
        return Err(Error::Refused {
            code: "conflict",
            message: "a provider of that id exists".to_owned(),
        });
    }
    write(&mut tx, &d, true, now).await?;
    audit(&mut tx, actor, "provider.created", &d, by_device).await?;
    tx.commit().await?;
    Ok(d)
}

/// Replaces a user definition (a new version). Accounts already stored keep the base URL they
/// were bound to.
pub async fn replace(
    pool: &SqlitePool,
    d: &Definition,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Definition, Error> {
    if let Some(why) = problem(d) {
        return bad(why);
    }
    let mut tx = super::begin_write(pool).await?;
    let old = get_in(&mut tx, &d.id).await?;
    let mut d = d.clone();
    (d.builtin, d.version) = (false, old.version + 1);
    if d.wire.is_empty() {
        d.wire = wire_for(&d.harness).to_owned();
    }
    if let Some(why) = rules::prefix_conflict(&mut tx, &d).await? {
        return bad(why);
    }
    // What a stored key was bound to, and how it is served, does not move under it: a definition
    // that has accounts keeps its harness, wire and key shape (delete the accounts to change them).
    if (old.harness, old.wire, old.key_prefix)
        != (d.harness.clone(), d.wire.clone(), d.key_prefix.clone())
    {
        let used: i64 = sqlx::query_scalar("SELECT count(*) FROM core_accounts WHERE provider = ?")
            .bind(&d.id)
            .fetch_one(&mut *tx)
            .await?;
        if used > 0 {
            return Err(Error::Refused {
                code: "conflict",
                message: "accounts use that provider: its harness, wire and key_prefix are fixed"
                    .to_owned(),
            });
        }
    }
    write(&mut tx, &d, false, now).await?;
    audit(&mut tx, actor, "provider.updated", &d, by_device).await?;
    tx.commit().await?;
    Ok(d)
}

/// Deletes a user definition that no account uses.
pub async fn delete(
    pool: &SqlitePool,
    id: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    if built_in().iter().any(|b| b.id == id) {
        return bad("a built-in provider cannot be deleted");
    }
    let mut tx = super::begin_write(pool).await?;
    let old = get_in(&mut tx, id).await?;
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM core_accounts WHERE provider = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if used > 0 {
        return Err(Error::Refused {
            code: "conflict",
            message: "accounts use that provider".to_owned(),
        });
    }
    sqlx::query("DELETE FROM core_provider_defs WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(&mut tx, actor, "provider.deleted", &old, by_device).await?;
    tx.commit().await?;
    Ok(())
}
