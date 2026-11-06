//! Tests of the connections store; the fixture is here, the cases in `tests/`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use sqlx::sqlite::SqlitePool;

use super::resolve::Context;
use super::*;
use crate::connections::adapter::Registry;
use crate::connections::fake;
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::connect;

mod crud;
mod grant_cases;
mod health_cases;
mod leak;
mod migration;
mod resolve_cases;
mod security;

pub(super) const NOW: &str = "2026-11-06T10:00:00.000Z";
/// Shapeless on purpose: the redactor must not be what hides a leak.
pub(super) const SECRET: &str = "c1probe-7f3a9d41e0b2c8a6";
pub(super) const REFRESH: &str = "c1refresh-91c4d2b7a6e1f035";

pub(super) struct Fx {
    pub pool: SqlitePool,
    pub sealer: SecretBox,
    pub reg: Registry,
    pub dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-conn-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    crate::store::settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    Fx {
        pool,
        sealer: SecretBox::new(&[7; 32]),
        reg: fake::registry(),
        dir,
    }
}

pub(super) fn w(now: &str) -> Who<'_> {
    ww(1, now)
}

/// As [`w`], acting in workspace `ws`.
pub(super) fn ww(ws: i64, now: &str) -> Who<'_> {
    Who {
        workspace: ws,
        by_device: "d_test",
        actor: AuditActor::System,
        now,
    }
}

/// A second workspace (user 2).
pub(super) async fn second_user(fx: &Fx) {
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&fx.pool)
        .await
        .unwrap();
}

/// The version of the credential now stored.
pub(super) async fn version(fx: &Fx, id: i64) -> i64 {
    sqlx::query_scalar("SELECT version FROM core_connection_secrets WHERE connection_id = ?")
        .bind(id)
        .fetch_one(&fx.pool)
        .await
        .unwrap()
}

/// `secs` after [`NOW`].
pub(super) fn at(secs: i64) -> String {
    iso_of_unix(unix_secs(NOW).unwrap() + secs)
}

pub(super) fn material(access: &str) -> Material {
    Material::new(access, Some(REFRESH), Some("2026-11-06T11:00:00Z")).unwrap()
}

pub(super) async fn make(fx: &Fx, kind: &str, name: &str) -> Connection {
    make_with(fx, kind, name, SECRET).await
}

pub(super) async fn make_with(fx: &Fx, kind: &str, name: &str, access: &str) -> Connection {
    let new = NewConnection {
        kind,
        name,
        label: "A test connection",
        auth_method: "token",
    };
    create(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new,
        &material(access),
        w(NOW),
    )
    .await
    .unwrap()
}

pub(super) fn code<T>(r: Result<T, crate::store::secrets::Error>) -> &'static str {
    match r {
        Err(crate::store::secrets::Error::Refused { code, .. }) => code,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

/// A member of workspace 1 asking for `cap`.
pub(super) fn cx(cap: &str) -> Context<'_> {
    Context {
        workspace: 1,
        user: 1,
        role: "member",
        agent: None,
        session: None,
        capability: cap,
        resource: None,
        allowlist: None,
    }
}

/// The audit actions written, oldest first.
pub(super) async fn actions(fx: &Fx) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'connection.%' ORDER BY seq",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap()
}

/// Grants `role` read access (or `caps`) on `id`.
pub(super) async fn grant_role(fx: &Fx, id: i64, role: &str, caps: Option<&[String]>) {
    let limits = grants::Limits::new();
    let new = grants::NewGrant {
        grantee_kind: "role",
        grantee: role,
        capabilities: caps,
        limits: &limits,
    };
    grants::set(&fx.pool, &fx.reg, id, &new, w(NOW))
        .await
        .unwrap();
}

pub(super) async fn bind(fx: &Fx, id: i64, scope: (&str, &str)) {
    bindings::set(&fx.pool, id, scope, w(NOW)).await.unwrap();
}

pub(super) static ALL_CAPS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| vec!["read_items".to_owned(), "write_items".to_owned()]);

/// Grants agent `agent` (read-only unless `caps`) on `id`, with `limits`.
pub(super) async fn grant_agent(
    fx: &Fx,
    id: i64,
    agent: &str,
    caps: Option<&[String]>,
    limits: &grants::Limits,
) {
    let new = grants::NewGrant {
        grantee_kind: "agent",
        grantee: agent,
        capabilities: caps,
        limits,
    };
    grants::set(&fx.pool, &fx.reg, id, &new, w(NOW))
        .await
        .unwrap();
}
