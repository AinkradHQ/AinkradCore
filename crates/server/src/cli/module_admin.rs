//! A module's admin commands on the composed binary: `<binary> <module id> <name> <db> [args…]`
//! (`Module::admin_commands`). They run under the Core's ops rules: only a module this build
//! carries and a command it declared (platform verbs are matched first, so a module cannot
//! shadow one), only on a database that exists (never created here), never beside a running
//! server, on the module's own migrated tables, and the module's output is printed as is.

use std::path::Path;
use std::sync::Arc;

use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::{self, migrate};

use super::{Result_, state_dir};

/// The module and command `args` name, if this build carries both.
pub(super) fn find<'a>(
    available: &'a [Arc<dyn Module>],
    args: &[&str],
) -> Option<&'a Arc<dyn Module>> {
    let [id, name, _db, ..] = args else {
        return None;
    };
    available
        .iter()
        .find(|m| m.id() == *id && m.admin_commands().contains(name))
}

/// The socket a server serving `db` is answering on, if any. A socket file nobody listens on
/// (a crashed server) is not a live one.
// ponytail: a custom `--listen unix:<path>` elsewhere is not found; a pid lock if that bites.
pub(crate) fn live_server(db: &Path) -> Option<std::path::PathBuf> {
    ["core.sock", "admin.sock"]
        .iter()
        .map(|n| state_dir(db).join(n))
        .find(|p| std::os::unix::net::UnixStream::connect(p).is_ok())
}

pub(super) async fn run(module: &Arc<dyn Module>, args: &[&str]) -> Result_ {
    let [_, name, db, rest @ ..] = args else {
        return Err("usage: <module> <command> <db> [args]".into());
    };
    let db = Path::new(db);
    if !db.is_file() {
        return Err(format!("{}: no database (init or serve creates it)", db.display()).into());
    }
    if let Some(sock) = live_server(db) {
        return Err(format!(
            "a server is running on {}: stop it before running {} {name}",
            sock.display(),
            module.id()
        )
        .into());
    }
    let pool = store::connect(db).await?;
    migrate::migrate_modules(&pool, std::slice::from_ref(module)).await?;
    let out = module.admin(name, &pool, rest).await;
    pool.close().await;
    println!("{}", out?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_listening_socket_is_a_live_server() {
        let dir = std::env::temp_dir().join(format!("core-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("core.db");
        assert!(live_server(&db).is_none(), "no socket");
        let listener = std::os::unix::net::UnixListener::bind(dir.join("core.sock")).unwrap();
        assert!(live_server(&db).is_some(), "a listener");
        drop(listener);
        assert!(
            live_server(&db).is_none(),
            "a stale socket file is not a server"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
