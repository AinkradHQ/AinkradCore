//! What a provider definition must satisfy for the auth gateway to serve its keys (KAN-435 G7,
//! design §5.1 to §5.3): the wire it speaks, the shape its keys start with, and the rules that keep
//! one key from being attributed to two providers. Validation only; the rows are `providers`'.

use ainkrad_proto::v2::key_prefix_problem;
use sqlx::SqliteConnection;

use super::providers::Definition;

/// The API dialects the gateway speaks: `ainkrad_proto::v2::Wire`, by its wire name.
pub const WIRES: [&str; 3] = ["anthropic-messages", "openai-responses", "gemini-generate"];

/// The longest `key_prefix` (see [`problem`]).
const MAX_PREFIX: usize = 16;

/// The wire a harness speaks to its provider (the one a definition of that harness must name).
pub fn wire_for(harness: &str) -> &'static str {
    match harness {
        "codex" => "openai-responses",
        "agy" => "gemini-generate",
        _ => "anthropic-messages",
    }
}

/// The host of a validated `https://host[:443][/path]` base URL.
pub fn host_of(base_url: &str) -> &str {
    let rest = base_url.strip_prefix("https://").unwrap_or(base_url);
    let host = rest.split('/').next().unwrap_or(rest);
    host.strip_suffix(":443").unwrap_or(host)
}

/// Why `d`'s wire or key prefix is not acceptable, if it is not. An empty wire is the harness's own.
pub fn problem(d: &Definition) -> Option<String> {
    if !d.wire.is_empty() && !WIRES.contains(&d.wire.as_str()) {
        return Some(format!("wire is one of {}", WIRES.join(", ")));
    }
    if !d.wire.is_empty() && d.wire != wire_for(&d.harness) {
        return Some(format!(
            "a {} definition speaks {}: the wire is its harness's own",
            d.harness,
            wire_for(&d.harness)
        ));
    }
    if let Some(p) = d.test_path.as_deref().filter(|p| !test_path_ok(p)) {
        return Some(format!(
            "test_path {p:?} is a path under the base URL: / then 1 to 99 of [A-Za-z0-9._~/-], \
             with no empty or dot segment"
        ));
    }
    let prefix = d.key_prefix.as_deref()?;
    if let Some(why) = key_prefix_problem(prefix) {
        return Some(why.to_owned());
    }
    // The prefix is shown to a `read` device with the definition: it is a vendor's constant marker,
    // never a stretch of a key that was pasted in its place.
    if prefix.len() > MAX_PREFIX {
        return Some(format!(
            "a key_prefix is the vendor's constant marker, at most {MAX_PREFIX} characters"
        ));
    }
    // A definition that can hold keys is served by the gateway only: an env key would put a user's
    // host in front of a key in the sandbox.
    (d.delivery.iter().any(|m| m == "env") || !d.delivery.iter().any(|m| m == "gateway"))
        .then(|| "a definition with a key_prefix holds keys through the gateway only: delivery is [\"gateway\"]".to_owned())
}

/// Whether `p` is a plain path for the one-shot test: no query, no dot segment, no escapes.
fn test_path_ok(p: &str) -> bool {
    (2..=100).contains(&p.len())
        && p.starts_with('/')
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~/-".contains(&b))
        && p[1..]
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

/// Why a model id is not acceptable, if it is not. The gateway compares a request's model with the
/// ids it was granted, exactly: an id is the one the provider answers to, not an alias it resolves
/// (`-latest`, a family name), and a routing suffix that makes the provider do more is refused
/// (OpenRouter's `:online` adds a web search the gateway can neither see nor price).
pub fn model_problem(id: &str) -> Option<&'static str> {
    id.to_ascii_lowercase()
        .ends_with(":online")
        .then_some("a model id may not end in :online (a provider-side web search)")
}

/// Another definition whose `key_prefix` equals, extends or is a prefix of `d`'s, if there is one:
/// a key could then be attributed to either, so the pair is refused whichever was stored first.
pub async fn prefix_conflict(
    conn: &mut SqliteConnection,
    d: &Definition,
) -> Result<Option<String>, sqlx::Error> {
    let Some(p) = d.key_prefix.as_deref() else {
        return Ok(None);
    };
    let others: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, key_prefix FROM core_provider_defs WHERE key_prefix IS NOT NULL AND id != ?",
    )
    .bind(&d.id)
    .fetch_all(conn)
    .await?;
    Ok(others
        .into_iter()
        .find(|(_, q)| q.starts_with(p) || p.starts_with(q.as_str()))
        .map(|(id, _)| {
            format!("the key_prefix collides with provider {id}'s: a key would belong to both")
        }))
}

/// Every user definition's declared key shape, host as the definition has it now.
pub async fn key_shapes(
    conn: &mut SqliteConnection,
) -> Result<Vec<(String, String, String)>, sqlx::Error> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, key_prefix, base_url FROM core_provider_defs WHERE key_prefix IS NOT NULL",
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, prefix, url)| (id, prefix, host_of(&url).to_owned()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_read_from_the_base_url() {
        assert_eq!(host_of("https://openrouter.ai/api/v1"), "openrouter.ai");
        assert_eq!(host_of("https://a.example.com:443"), "a.example.com");
        assert_eq!(host_of("https://a.example.com"), "a.example.com");
    }

    #[test]
    fn the_online_suffix_is_refused_in_any_case() {
        for id in ["vendor/m:online", "m:ONLINE"] {
            assert!(model_problem(id).is_some(), "{id}");
        }
        for id in ["vendor/m", "vendor/m:floor", "online", "m:online-x"] {
            assert_eq!(model_problem(id), None, "{id}");
        }
    }
}
