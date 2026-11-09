//! A module's own settings (`Module::settings`): integers with a default and bounds, kept in
//! the platform's settings table under `module.<id>.<name>` at the server scope. A module reads
//! and writes only the names it declared, through its own [`ModuleSettings`], so it can neither
//! see nor touch a platform key or another module's. A write is audited as `setting.set` /
//! `setting.reset` with the full key, like a platform setting; the platform's registry, its
//! listing and its history never see these keys.

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_core::settings::SettingError;
use serde_json::json;
use sqlx::{SqliteConnection, SqlitePool};

use super::audit;
use super::settings::SetError;
use crate::module::{Module, ModuleSetting};

/// The prefix of every module key in the settings table; no platform name starts with it.
pub const PREFIX: &str = "module.";

/// One module's settings handle.
#[derive(Debug, Clone, Copy)]
pub struct ModuleSettings {
    id: &'static str,
    specs: &'static [ModuleSetting],
}

impl ModuleSettings {
    pub fn of(m: &dyn Module) -> Self {
        Self {
            id: m.id(),
            specs: m.settings(),
        }
    }

    fn spec(&self, name: &str) -> Result<&'static ModuleSetting, SetError> {
        self.specs
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| SetError::Refused(SettingError::UnknownKey(name.to_owned())))
    }

    fn key(&self, name: &str) -> String {
        format!("{PREFIX}{}.{name}", self.id)
    }

    /// `name`'s value: the stored one if it is still in bounds, else the default.
    pub async fn get(&self, pool: &SqlitePool, name: &str) -> Result<i64, SetError> {
        self.get_in(&mut *pool.acquire().await?, name).await
    }

    /// [`get`](Self::get) inside the caller's transaction.
    pub async fn get_in(&self, conn: &mut SqliteConnection, name: &str) -> Result<i64, SetError> {
        let spec = self.spec(name)?;
        Ok(self.stored(conn, name).await?.map_or(spec.default, |v| {
            if (spec.min..=spec.max).contains(&v) {
                v
            } else {
                spec.default
            }
        }))
    }

    async fn stored(
        &self,
        conn: &mut SqliteConnection,
        name: &str,
    ) -> Result<Option<i64>, sqlx::Error> {
        let v: Option<String> = sqlx::query_scalar(
            "SELECT value FROM settings WHERE key = ? AND scope_kind = 'server' AND scope_id = 0",
        )
        .bind(self.key(name))
        .fetch_optional(&mut *conn)
        .await?;
        Ok(v.and_then(|v| v.parse().ok()))
    }

    /// Sets `name` to `value` (JSON text), refused with the reason when out of bounds or not an
    /// integer; audited. Returns the new value.
    pub async fn set(
        &self,
        pool: &SqlitePool,
        name: &str,
        value: &str,
        actor: AuditActor,
        now: &str,
    ) -> Result<i64, SetError> {
        let spec = self.spec(name)?;
        let not_integer = || {
            SetError::Refused(SettingError::NotInteger {
                key: spec.name,
                value: value.to_owned(),
            })
        };
        let v: i64 = value.trim().parse().map_err(|_| not_integer())?;
        if !(spec.min..=spec.max).contains(&v) {
            return Err(SetError::Refused(SettingError::OutOfBounds {
                key: spec.name,
                value: v,
                min: spec.min,
                max: spec.max,
            }));
        }
        self.write(pool, name, Some(v), actor, now).await?;
        Ok(v)
    }

    /// Removes the stored value, so the default holds again; a reset of a value never set
    /// changes and audits nothing. Returns the default.
    pub async fn reset(
        &self,
        pool: &SqlitePool,
        name: &str,
        actor: AuditActor,
        now: &str,
    ) -> Result<i64, SetError> {
        let spec = self.spec(name)?;
        self.write(pool, name, None, actor, now).await?;
        Ok(spec.default)
    }

    async fn write(
        &self,
        pool: &SqlitePool,
        name: &str,
        new: Option<i64>,
        actor: AuditActor,
        now: &str,
    ) -> Result<(), SetError> {
        let key = self.key(name);
        let mut tx = super::begin_write(pool).await?;
        let old = self.stored(&mut tx, name).await?;
        if new.is_none() && old.is_none() {
            return Ok(());
        }
        let (by_kind, by_id) = actor.parts();
        match new {
            Some(v) => sqlx::query(
                "INSERT INTO settings (key, scope_kind, scope_id, value, updated_by_kind, \
                 updated_by_id, updated_at) VALUES (?, 'server', 0, ?, ?, ?, ?) \
                 ON CONFLICT (key, scope_kind, scope_id) DO UPDATE SET value = excluded.value, \
                 updated_by_kind = excluded.updated_by_kind, \
                 updated_by_id = excluded.updated_by_id, updated_at = excluded.updated_at",
            )
            .bind(&key)
            .bind(v.to_string())
            .bind(by_kind)
            .bind(by_id)
            .bind(now),
            None => sqlx::query(
                "DELETE FROM settings WHERE key = ? AND scope_kind = 'server' AND scope_id = 0",
            )
            .bind(&key),
        }
        .execute(&mut *tx)
        .await?;
        let event = NewAuditEvent {
            actor,
            action: if new.is_some() {
                "setting.set"
            } else {
                "setting.reset"
            }
            .to_owned(),
            entity: None,
            details: json!({"key": key, "scope": "server", "old": old, "new": new, "at": now})
                .to_string(),
        };
        audit::append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ainkrad_core::ids::UserId;
    use ainkrad_core::settings::REGISTRY;
    use axum::Router;

    use super::*;
    use crate::api::App;
    use crate::store::connect;

    const NOW: &str = "2026-10-22T10:00:00.000Z";
    const BY: AuditActor = AuditActor::User(UserId(1));

    struct Toy(&'static str);

    impl Module for Toy {
        fn id(&self) -> &'static str {
            self.0
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn settings(&self) -> &'static [ModuleSetting] {
            &[ModuleSetting {
                name: "budget.warn_pct",
                default: 80,
                min: 1,
                max: 100,
                description: "warn at",
            }]
        }
    }

    async fn pool() -> (SqlitePool, std::path::PathBuf) {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("core-modset-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        (connect(&dir.join("core.db")).await.unwrap(), dir)
    }

    #[test]
    fn no_platform_name_can_collide_with_a_module_key() {
        assert!(REGISTRY.iter().all(|s| !s.name.starts_with(PREFIX)));
    }

    #[tokio::test]
    async fn a_module_reads_defaults_and_sets_audited_bounded_values() {
        let (pool, dir) = pool().await;
        let s = ModuleSettings::of(&Toy("toy"));
        assert_eq!(s.get(&pool, "budget.warn_pct").await.unwrap(), 80);
        assert_eq!(
            s.set(&pool, "budget.warn_pct", "90", BY, NOW)
                .await
                .unwrap(),
            90
        );
        assert_eq!(s.get(&pool, "budget.warn_pct").await.unwrap(), 90);
        for bad in ["0", "101", "x", "1.5"] {
            assert!(
                matches!(
                    s.set(&pool, "budget.warn_pct", bad, BY, NOW).await,
                    Err(SetError::Refused(_))
                ),
                "{bad}"
            );
        }
        assert_eq!(
            s.get(&pool, "budget.warn_pct").await.unwrap(),
            90,
            "refusals changed nothing"
        );
        let key = "module.toy.budget.warn_pct";
        let audited: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE action = 'setting.set' \
             AND json_extract(details, '$.key') = ?",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audited, 1);
        assert_eq!(
            s.reset(&pool, "budget.warn_pct", BY, NOW).await.unwrap(),
            80
        );
        assert_eq!(s.get(&pool, "budget.warn_pct").await.unwrap(), 80);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A module reaches only the names it declared: not a platform key, not another module's.
    #[tokio::test]
    async fn a_module_cannot_name_a_key_it_did_not_declare() {
        let (pool, dir) = pool().await;
        let toy = ModuleSettings::of(&Toy("toy"));
        let other = ModuleSettings::of(&Toy("other"));
        toy.set(&pool, "budget.warn_pct", "55", BY, NOW)
            .await
            .unwrap();
        // The other module's same-named setting is its own row.
        assert_eq!(other.get(&pool, "budget.warn_pct").await.unwrap(), 80);
        for name in [
            "api.request_burst",
            "module.toy.budget.warn_pct",
            "nope",
            "",
        ] {
            assert!(
                matches!(toy.get(&pool, name).await, Err(SetError::Refused(_))),
                "{name}"
            );
            assert!(
                matches!(
                    toy.set(&pool, name, "5", BY, NOW).await,
                    Err(SetError::Refused(_))
                ),
                "{name}"
            );
            assert!(
                matches!(
                    toy.reset(&pool, name, BY, NOW).await,
                    Err(SetError::Refused(_))
                ),
                "{name}"
            );
        }
        // Platform settings see none of it.
        let platform = crate::store::settings::list(&pool, ainkrad_core::settings::Scope::Server)
            .await
            .unwrap();
        assert_eq!(platform.len(), REGISTRY.len());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A stored value that is out of bounds (the bounds changed) falls back to the default.
    #[tokio::test]
    async fn a_stale_out_of_bounds_row_reads_as_the_default() {
        let (pool, dir) = pool().await;
        sqlx::query(
            "INSERT INTO settings (key, scope_kind, scope_id, value, updated_by_kind, updated_at) \
             VALUES ('module.toy.budget.warn_pct', 'server', 0, '500', 'system', 'x')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let s = ModuleSettings::of(&Toy("toy"));
        assert_eq!(s.get(&pool, "budget.warn_pct").await.unwrap(), 80);
        let _ = std::fs::remove_dir_all(dir);
    }
}
