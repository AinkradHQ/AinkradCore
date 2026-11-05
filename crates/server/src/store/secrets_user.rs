//! The broker's key-to-host binding, and its rule for keys of user-defined providers (KAN-435 G7,
//! design §5.3). `ainkrad_proto::v2::key_host_problem` is the one rule; the runner applies it again
//! before dialing, with the same inputs.
//!
//! - A **user provider's** key is stored only through the account model (`acct.<provider>.<id>`,
//!   whose row holds the frozen host), only when the definition declares a `key_prefix` and is
//!   delivered through the gateway, and only when it matches that prefix and the account's host.
//! - A **built-in provider's** key of a known shape (`sk-`, `AIza`) must belong to that provider and
//!   its frozen host: an Anthropic key under an OpenAI account, or an OpenRouter key (a declared user
//!   prefix) under `openai`, is refused. A value with no known shape (a throwaway, an OAuth token) is
//!   left to the shape check, as before.

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{UserKeyHost, account_provider, key_host_problem};
use sqlx::SqliteConnection;

use super::gateway::account_secret;
use super::provider_rules::{host_of, key_shapes};
use super::secrets::{ACCOUNT_PREFIX, ACCOUNT_PROVIDERS, Error};

fn refused<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code: "bad_request",
        message: message.into(),
    })
}

fn builtin(provider: &str) -> bool {
    ACCOUNT_PROVIDERS.iter().any(|(k, _)| *k == provider)
}

/// Whether `name` is `acct.<id>.<label>` of a stored user definition (`kind_of` knows only the
/// three built-ins).
pub(super) async fn holds(conn: &mut SqliteConnection, name: &str) -> Result<bool, Error> {
    let Some(provider) = account_provider(name).filter(|p| !builtin(p)) else {
        return Ok(false);
    };
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_provider_defs WHERE id = ?")
        .bind(provider)
        .fetch_one(conn)
        .await?;
    Ok(n > 0)
}

/// The key-to-host rule for the account secret `name` holding `value`; nothing for any other secret.
pub(super) async fn bind(
    conn: &mut SqliteConnection,
    name: &str,
    value: &str,
) -> Result<(), Error> {
    let Some(provider) = name
        .strip_prefix(ACCOUNT_PREFIX)
        .and_then(|_| account_provider(name))
    else {
        return Ok(());
    };
    let user = !builtin(provider);
    let key = value.trim();
    // A built-in provider's throwaway or OAuth token has no shape this rule knows.
    if !user && !(key.starts_with("sk-") || key.starts_with("AIza")) {
        return Ok(());
    }
    let account = account_secret(name).map(|(_, id)| id);
    let frozen: Option<String> = match account {
        Some(id) => {
            sqlx::query_scalar("SELECT base_url FROM core_accounts WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?
        }
        None => None,
    };
    let Some(url) = frozen else {
        return match user {
            true => refused(
                "a user provider's key is stored through the accounts API, as acct.<provider>.<id>",
            ),
            false => Ok(()),
        };
    };
    let shapes = key_shapes(conn).await?;
    if user && !shapes.iter().any(|(id, _, _)| id == provider) {
        return refused(
            "this provider declares no key_prefix, so it holds no key: set one (and deliver through \
             the gateway) first",
        );
    }
    let host = host_of(&url);
    // The account's own provider is judged against the host its key was bound to, not the
    // definition's current one.
    let list: Vec<UserKeyHost> = shapes
        .iter()
        .map(|(id, prefix, h)| UserKeyHost {
            provider: id,
            prefix,
            host: if id == provider { host } else { h },
        })
        .collect();
    match key_host_problem(key, provider, host, &list) {
        Some(why) => refused(format!(
            "{why}: a key is stored only for the provider and host its shape names"
        )),
        None => Ok(()),
    }
}

/// The longest value the shape check scans for a key glued behind another (it is quadratic).
const MAX_ACCOUNT_SCAN: usize = 512;

/// Whether `value` as a whole is one key of the provider's own `shape` and nothing else: the
/// redactor sees exactly that key, and no other shape starts anywhere inside it (the redactor
/// reads a glued `-----BEGIN` or `ghp_` as part of one token, so each tail is tried on its own).
pub(super) fn single_own_key(redactor: &Redactor, value: &str, shape: &str) -> bool {
    let value = value.trim();
    value.len() <= MAX_ACCOUNT_SCAN
        && redactor.text(value) == format!("[redacted:{shape}]")
        && value
            .char_indices()
            .skip(1)
            .all(|(i, _)| redactor.text(&value[i..]) == value[i..])
}

/// Whether `value` as a whole is one key of the one shape the redactor reads in it (a user
/// provider's key has no shape of its own to name: it is judged as what the redactor sees).
pub(super) fn single_key(redactor: &Redactor, value: &str) -> bool {
    let value = value.trim();
    redactor
        .text(value)
        .strip_prefix("[redacted:")
        .and_then(|s| s.strip_suffix(']'))
        .is_some_and(|shape| single_own_key(redactor, value, shape))
}
