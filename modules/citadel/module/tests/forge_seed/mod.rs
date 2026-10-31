//! A Core with Citadel, a company with a project and an issue, a fake GitHub (or a server of the
//! test's own) and the forge runtime pointed at it with a broker secret holding the token.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::api::v1::BY;
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::store::secrets::{self, NewValue};
use ainkrad_providers::fake::{self, Hub, Shared};
use ainkrad_providers::guard::Policy;
use citadel_module::domain::work::ProjectId;
use citadel_module::forge::Runtime;
use citadel_module::store::forge::{PushReporter, push_reported};
use citadel_module::store::work::{Commands, ProjectForge, Repo, add_repo};

pub use crate::common::*;
pub use crate::gov_seed::*;

pub const TOKEN: &str = "forge_token";
pub const SECRET: &str = "citadel.forge.token";

/// The address a fake's API URL (`http://127.0.0.1:port`) names.
pub fn addr_of(api: &str) -> SocketAddr {
    api.trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

pub struct Rig {
    pub fx: Fx,
    pub s: Seed,
    pub rt: Arc<Runtime>,
    pub sealer: Arc<SecretBox>,
    pub api: String,
    pub hub: Shared<Hub>,
    /// The repo `app` of the project, on the fake.
    pub repo: i64,
}

/// The broker on (throwaway mode) with `citadel.forge` holding [`TOKEN`], and a sealer.
pub async fn broker(fx: &Fx) -> Arc<SecretBox> {
    let sealer = Arc::new(SecretBox::new(&[7; 32]));
    ainkrad_core_server::store::settings::set(
        &fx.app.pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        BY,
        NOW,
    )
    .await
    .unwrap();
    let new = NewValue {
        value: TOKEN,
        runners: None,
        delivery: None,
    };
    secrets::create(
        &fx.app.pool,
        &sealer,
        SECRET,
        &new,
        &fx.dev.id,
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    sealer
}

pub async fn add_forge_repo(
    fx: &Fx,
    project: ProjectId,
    (name, forge_repo): (&str, &str),
    api: &str,
    secret: &str,
) -> i64 {
    let repo = Repo {
        id: 0,
        project_id: project,
        name: name.to_owned(),
        url: format!("https://example.test/{forge_repo}.git"),
        default_branch: "main".to_owned(),
        position: 0,
        primary: false,
        forge: Some(ProjectForge {
            project_id: project,
            kind: "github".to_owned(),
            api_url: api.to_owned(),
            repo: forge_repo.to_owned(),
            secret: secret.to_owned(),
        }),
        commands: Commands::default(),
    };
    add_repo(&fx.app.pool, &repo, BY).await.unwrap().unwrap().id
}

/// A rig on a fake GitHub that wants [`TOKEN`].
pub async fn rig() -> Rig {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "AAA").await;
    let sealer = broker(&fx).await;
    let (api, hub) = fake::github(TOKEN).await;
    let policy = Policy::new([]).with_test_origin(addr_of(&api));
    let rt = Runtime::with_policy(fx.app.pool.clone(), sealer.clone(), policy);
    let repo = add_forge_repo(&fx, s.project, ("app", "acme/core"), &api, SECRET).await;
    Rig {
        fx,
        s,
        rt,
        sealer,
        api,
        hub,
        repo,
    }
}

impl Rig {
    pub fn pool(&self) -> &sqlx::SqlitePool {
        &self.fx.app.pool
    }

    /// Asks for the issue's PR and reports its branch pushed at `sha`: due at the next pass.
    pub async fn requested(&self, sha: &str) {
        let pr = citadel_module::store::forge::request_pr(
            self.pool(),
            self.s.issue,
            None,
            self.s.agent,
            ("Ship it", "Body"),
        )
        .await
        .unwrap();
        self.pushed(&pr.head, sha).await;
    }

    pub async fn pushed(&self, branch: &str, sha: &str) {
        let by = PushReporter {
            issue: self.s.issue,
            agent: self.s.agent,
            run: None,
        };
        let payload = serde_json::json!({"type": "branch_pushed", "repo": "app",
                                         "branch": branch, "sha": sha});
        push_reported(self.pool(), by, &payload, NOW).await.unwrap();
    }

    pub async fn sync(&self) {
        citadel_module::forge::forge_sync(&self.rt).await.unwrap();
    }

    pub async fn pr(&self) -> citadel_module::store::forge::IssuePr {
        citadel_module::store::forge::issue_pr(self.pool(), self.s.issue)
            .await
            .unwrap()
            .unwrap()
    }
}

/// Every byte the database holds on disk (main file and write-ahead log), for "the token is not
/// in it" checks.
pub async fn db_bytes(fx: &Fx) -> Vec<u8> {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let mut all = std::fs::read(fx.dir.join("core.db")).unwrap();
    all.extend(std::fs::read(fx.dir.join("core.db-wal")).unwrap_or_default());
    all
}

pub fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Stores broker secret `name` holding `value`.
pub async fn add_secret(fx: &Fx, sealer: &SecretBox, name: &str, value: &str) {
    let new = NewValue {
        value,
        runners: None,
        delivery: None,
    };
    secrets::create(
        &fx.app.pool,
        sealer,
        name,
        &new,
        &fx.dev.id,
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
}
