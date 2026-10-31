//! The module admin hook on the composed binary: `ainkrad-core-citadel citadel seed <db> <file>`
//! (E2-14 bootstrap). Idempotent, no credentials in or out of a seed, and refused beside a
//! running server and on a database that does not exist.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_ainkrad-core-citadel");

struct Home(PathBuf);

impl Home {
    /// Runs the module's migrations as a first `serve --enable-module citadel` would.
    async fn enabled(self) -> Self {
        let pool = ainkrad_core_server::store::connect(&self.db())
            .await
            .unwrap();
        let modules: Vec<std::sync::Arc<dyn ainkrad_core_server::module::Module>> =
            vec![std::sync::Arc::new(citadel_module::Citadel::default())];
        ainkrad_core_server::store::migrate::migrate_modules(&pool, &modules)
            .await
            .unwrap();
        pool.close().await;
        self
    }
    async fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("core-citadel-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = ainkrad_core_server::store::connect(&dir.join("core.db"))
            .await
            .unwrap();
        pool.close().await;
        Self(dir)
    }
    fn db(&self) -> PathBuf {
        self.0.join("core.db")
    }
    fn seed(&self, text: &str) -> PathBuf {
        let p = self.0.join("seed.toml");
        std::fs::write(&p, text).unwrap();
        p
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN).args(args).output().unwrap()
    }
    fn seed_cmd(&self, file: &Path) -> Output {
        self.run(&[
            "citadel",
            "seed",
            self.db().to_str().unwrap(),
            file.to_str().unwrap(),
        ])
    }
    async fn count(&self, table: &str) -> i64 {
        let pool = ainkrad_core_server::store::connect(&self.db())
            .await
            .unwrap();
        let n = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(&pool)
            .await
            // A table that was never migrated holds nothing.
            .unwrap_or(0);
        pool.close().await;
        n
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const SEED: &str = "[[companies]]\nname = \"Ainkrad\"\nkind = \"own\"\n";

#[tokio::test]
async fn the_seed_is_idempotent_and_creates_no_credentials() {
    let home = Home::new("seed").await.enabled().await;
    let file = home.seed(SEED);
    let first = home.seed_cmd(&file);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(String::from_utf8_lossy(&first.stdout).contains("1 added"));
    let second = home.seed_cmd(&file);
    assert!(second.status.success());
    assert!(String::from_utf8_lossy(&second.stdout).contains("0 added"));
    assert_eq!(home.count("citadel_companies").await, 1);
    // No default credentials: no device, pairing or secret came with it.
    for table in ["core_devices", "core_pairings", "core_secrets"] {
        assert_eq!(home.count(table).await, 0, "{table}");
    }
}

#[tokio::test]
async fn a_seed_with_a_credential_or_a_bad_row_changes_nothing() {
    let home = Home::new("bad").await.enabled().await;
    for text in [
        "[[companies]]\nname = \"X\"\npassword = \"hunter2\"\n",
        "token = \"abc\"\n",
        "[[companies]]\nname = \"Good\"\n[[companies]]\nname = \"Bad\"\nkind = \"evil\"\n",
    ] {
        let out = home.seed_cmd(&home.seed(text));
        assert!(!out.status.success(), "{text}");
    }
    assert_eq!(home.count("citadel_companies").await, 0);
}

#[tokio::test]
async fn it_refuses_a_running_server_and_a_missing_database() {
    let home = Home::new("live").await.enabled().await;
    let file = home.seed(SEED);
    let listener = std::os::unix::net::UnixListener::bind(home.0.join("core.sock")).unwrap();
    let out = home.seed_cmd(&file);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("server is running"));
    drop(listener);
    assert_eq!(home.count("citadel_companies").await, 0, "nothing written");
    // A stale socket file is not a server.
    assert!(home.seed_cmd(&file).status.success());

    let missing = home.0.join("none").join("core.db");
    let out = home.run(&[
        "citadel",
        "seed",
        missing.to_str().unwrap(),
        file.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(!missing.exists(), "the hook never creates a database");
}

#[tokio::test]
async fn an_unknown_command_or_module_is_a_usage_error() {
    let home = Home::new("usage").await;
    let db = home.db();
    for args in [["citadel", "nope"], ["nomodule", "seed"]] {
        let out = home.run(&[args[0], args[1], db.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

#[tokio::test]
async fn it_refuses_a_database_a_server_holds_or_a_module_that_is_not_enabled() {
    // Not enabled: the hook never creates the module's schema.
    let plain = Home::new("plain").await;
    let out = plain.seed_cmd(&plain.seed(SEED));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not enabled"));
    assert_eq!(plain.count("citadel_companies").await, 0);

    // A server holds `<db>.lock` whatever its socket: the hook is refused.
    let home = Home::new("locked").await.enabled().await;
    let lock = std::fs::File::create(home.0.join("core.db.lock")).unwrap();
    lock.lock().unwrap();
    let out = home.seed_cmd(&home.seed(SEED));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("in use"));
    assert_eq!(home.count("citadel_companies").await, 0);
    drop(lock);
    assert!(home.seed_cmd(&home.seed(SEED)).status.success());
}
