//! Settings commands (E15.17): every limit, quota and threshold, read and changed from a shell
//! as the admin, through the same audited store calls as `/api/v1/settings`.

use std::path::Path;

use citadel_core::audit::AuditActor;
use citadel_core::settings::{Key, Scope};
use citadel_server::scheduler::{Clock, SystemClock};
use citadel_server::store::{self, settings};

use super::{ADMIN, flags};
use crate::Result_;

pub const USAGE: &str = "  citadel-server setting list <db> [--scope <scope>]
  citadel-server setting get <db> <key> [--scope <scope>]
  citadel-server setting set <db> <key> <value> [--scope <scope>]
  citadel-server setting reset <db> <key> [--scope <scope>]
  citadel-server setting history <db> <key> [--scope <scope>]
A scope is server (the default), company:<id>, project:<id>, runner:<id> or account:<id>; the
most specific scope with a value wins (project, then company, then server; a runner's or an
account's own, then the server's). list prints one line per setting that may be set at the
scope: key, effective value, unit, where it comes from, bounds, the scopes it may be set at.
A value out of bounds or at a scope the setting does not allow is refused, never clamped.
reset removes the scope's own value, so it inherits again. history lists the sets and resets
(all scopes unless --scope), newest first. Every set and reset is audited.";

const BY: AuditActor = AuditActor::User(ADMIN);

/// Runs a settings command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    let (verb, db, key, value, rest) = match args {
        ["setting", "list", db, rest @ ..] => ("list", *db, None, None, rest),
        ["setting", "set", db, key, value, rest @ ..] => {
            ("set", *db, Some(*key), Some(*value), rest)
        }
        [
            "setting",
            verb @ ("get" | "reset" | "history"),
            db,
            key,
            rest @ ..,
        ] => (*verb, *db, Some(*key), None, rest),
        _ => return None,
    };
    let f = flags(rest, &["--scope"])?;
    let scope: Option<Scope> = match f.get("--scope") {
        Some(s) => Some(s.parse().ok()?),
        None => None,
    };
    let key = match key.map(str::parse::<Key>) {
        Some(Ok(k)) => Some(k),
        Some(Err(e)) => return Some(Err(e.into())),
        None => None,
    };
    Some(command(Path::new(db), verb, key, value, scope).await)
}

async fn command(
    db: &Path,
    verb: &str,
    key: Option<Key>,
    value: Option<&str>,
    scope: Option<Scope>,
) -> Result_ {
    let pool = store::connect(db).await?;
    let at = scope.unwrap_or(Scope::Server);
    let now = SystemClock.now();
    match (verb, key) {
        ("list", _) => {
            for e in settings::list(&pool, at).await? {
                println!("{}", line(&e));
            }
        }
        ("get", Some(k)) => println!("{}", line(&settings::effective(&pool, k, at).await?)),
        ("set", Some(k)) => {
            let e = settings::set(&pool, k, at, value.unwrap_or_default(), BY, &now).await?;
            eprintln!("{} set at {at}", k.name());
            println!("{}", line(&e));
        }
        ("reset", Some(k)) => {
            let e = settings::reset(&pool, k, at, BY, &now).await?;
            eprintln!("{} reset at {at}; it inherits", k.name());
            println!("{}", line(&e));
        }
        ("history", Some(k)) => {
            for c in settings::history(&pool, k, scope).await? {
                let shown = |v: Option<i64>| v.map_or("inherited".to_owned(), |v| v.to_string());
                println!(
                    "{}\t{}\t{}\t{} -> {}\tby {:?}",
                    c.at,
                    c.key,
                    c.scope,
                    shown(c.old),
                    shown(c.new),
                    c.actor
                );
            }
        }
        _ => unreachable!("run matched the verb"),
    }
    Ok(())
}

/// key, value, unit, source, bounds, scopes; tab-separated.
fn line(e: &settings::Effective) -> String {
    let scopes: Vec<&str> = e.spec.scopes.iter().map(|s| s.as_str()).collect();
    format!(
        "{}\t{}\t{}\t{}\t{}..={}\t{}",
        e.spec.name,
        e.value,
        e.spec.unit.as_str(),
        e.source.map_or("default".to_owned(), |s| s.to_string()),
        e.spec.min,
        e.spec.max,
        scopes.join(",")
    )
}
