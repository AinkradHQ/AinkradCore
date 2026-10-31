//! A migrated database for the module's tests: the platform's migrations, then Citadel's.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::{connect, migrate};
use sqlx::SqlitePool;

use crate::Citadel;

/// A migrated database in its own temp dir, removed on drop.
pub struct Db {
    pub pool: SqlitePool,
    dir: PathBuf,
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("citadel-module-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Citadel::default())];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    Db { pool, dir }
}
