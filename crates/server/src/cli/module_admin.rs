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

/// The socket a server serving `db` may be answering on, if any. Fails closed: only a refused
/// connection or a missing socket (a crashed server leaves the file) means nobody is there; any
/// other error (a 0600 socket of another user, a full backlog) means a server may be running.
pub(crate) fn live_server(db: &Path) -> Option<std::path::PathBuf> {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    ["core.sock", "admin.sock"]
        .iter()
        .map(|n| state_dir(db).join(n))
        .find(|p| match std::os::unix::net::UnixStream::connect(p) {
            Ok(_) => true,
            Err(e) => !matches!(e.kind(), ConnectionRefused | NotFound),
        })
}

/// An exclusive lock on `<db>.lock`, held for the life of the returned file: `serve` takes it
/// for its whole run and an admin hook for its command, so a hook can never run beside a server
/// whatever its `--listen` (a custom socket included), and a server starting at the same moment
/// loses cleanly. The kernel drops it with the process.
pub(crate) fn lock(db: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = db.as_os_str().to_owned();
    name.push(".lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(name)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::other(format!(
            "{} is in use by a server or another admin command",
            db.display()
        ))),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

pub(super) async fn run(module: &Arc<dyn Module>, args: &[&str]) -> Result_ {
    let [_, name, db, rest @ ..] = args else {
        return Err("usage: <module> <command> <db> [args]".into());
    };
    let db = Path::new(db);
    if !db.is_file() {
        return Err(format!("{}: no database (init or serve creates it)", db.display()).into());
    }
    // The database's owner only, checked before it is opened: another user's run would leave
    // its own -wal/-shm files that the service user then cannot open.
    super::admin::bootstrap::owner_only(db)?;
    let _held = lock(db)?;
    if let Some(sock) = live_server(db) {
        return Err(format!(
            "a server may be running on {}: stop it before running {} {name}",
            sock.display(),
            module.id()
        )
        .into());
    }
    let pool = store::connect(db).await?;
    // Only a module a server has already run on this database: never create its schema here.
    let table = format!("_migrations_{}", module.id());
    let enabled: Option<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(&table)
            .fetch_optional(&pool)
            .await?;
    if enabled.is_none() {
        pool.close().await;
        return Err(format!(
            "module {} is not enabled on this database (serve --enable-module {} first)",
            module.id(),
            module.id()
        )
        .into());
    }
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

    #[test]
    fn the_database_lock_is_exclusive_and_released_with_its_holder() {
        let dir = std::env::temp_dir().join(format!("core-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("core.db");
        let held = lock(&db).unwrap();
        assert!(lock(&db).is_err(), "a second holder is refused");
        drop(held);
        assert!(lock(&db).is_ok(), "released");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
