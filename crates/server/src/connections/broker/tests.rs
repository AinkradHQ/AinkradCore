//! Broker tests: loopback fakes speak for GitHub and Jira (no network, no real token); the
//! credentials are shapeless on purpose, so the redactor is never what hides a leak. The cases
//! are in `tests/`.

use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::{ToolCall, ToolResult};
use serde_json::{Value, json};

use super::*;
use crate::connections::adapter::Registry;
use crate::connections::github::tests::fake::Fake as GhFake;
use crate::connections::jira::tests as jt;
use crate::connections::material::Material;
use crate::store::agents::{self as sessions, NewSession};
use crate::store::connections::grants::{self, Limits as Wall, NewGrant};
use crate::store::connections::{Connection, NewConnection, Who, bindings, create};

mod authz;
mod c6_adversarial;
mod health_cases;
mod leak;
mod limits_cases;
mod linear;
mod path;

pub const NOW: &str = "2026-11-06T10:00:00.000Z";
pub const GH_TOKEN: &str = "gh1probe-7f3a9d41e0b2c8a6";
pub const GH_TOKEN_2: &str = "gh2probe-5d2e8b0c7a41f913";
pub const RUNNER: &str = "d_aaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const OTHER_RUNNER: &str = "d_bbbbbbbbbbbbbbbbbbbbbbbbbb";

pub struct Fx {
    pub j: jt::Fx,
    pub gh: GhFake,
    pub b: Broker,
    pub reg: Registry,
}

fn who() -> Who<'static> {
    Who {
        workspace: 1,
        by_device: "d_test",
        actor: AuditActor::System,
        now: NOW,
    }
}

pub async fn fx_with(limits: Limits) -> Fx {
    fx_app(limits, false).await
}

/// With Sign in with Atlassian configured when `app`.
pub async fn fx_app(limits: Limits, app: bool) -> Fx {
    let j = jt::fx(app).await;
    let gh = GhFake::start().await;
    let github = Github::new(Arc::new(gh.transport()));
    let mut reg = Registry::new();
    reg.register(Arc::new(github.clone())).unwrap();
    reg.register(j.jira.clone()).unwrap();
    let b = Broker::with(reg.clone(), github, j.jira.clone(), limits);
    for (id, name) in [(RUNNER, "r1"), (OTHER_RUNNER, "r2")] {
        sqlx::query(
            "INSERT INTO core_devices (id, kind, name, routine_spki, fingerprint, status) \
             VALUES (?, 'runner', ?, randomblob(91), substr(hex(randomblob(22)), 1, 43), 'active')",
        )
        .bind(id)
        .bind(name)
        .execute(&j.pool)
        .await
        .unwrap();
    }
    Fx { j, gh, b, reg }
}

pub async fn fx() -> Fx {
    fx_with(Limits::default()).await
}

impl Fx {
    pub fn env(&self) -> Env<'_> {
        Env {
            pool: &self.j.pool,
            sealer: Some(&self.j.sealer),
            now: NOW,
        }
    }

    /// A GitHub connection holding `token`.
    pub async fn github(&self, name: &str, token: &str) -> Connection {
        let m = Material::new(token, None, None).unwrap();
        let new = NewConnection {
            kind: "github",
            name,
            label: "A GitHub account",
            auth_method: "token",
        };
        create(&self.j.pool, &self.j.sealer, &self.reg, &new, &m, who())
            .await
            .unwrap()
    }

    /// A token-auth Jira connection to `acme.atlassian.net`.
    pub async fn jira(&self, name: &str) -> Connection {
        let new = NewConnection {
            kind: "jira",
            name,
            label: "A Jira site",
            auth_method: "token",
        };
        let m = jt::basic();
        create(&self.j.pool, &self.j.sealer, &self.reg, &new, &m, who())
            .await
            .unwrap()
    }

    /// Grants `grantee` (`user`, `role` or `agent`) capabilities and limits on a connection.
    pub async fn grant(
        &self,
        id: i64,
        (kind, who_): (&str, &str),
        caps: &[&str],
        limits: &[(&str, &[&str])],
    ) {
        let caps: Vec<String> = caps.iter().map(|c| (*c).to_owned()).collect();
        let limits: Wall = limits
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.iter().map(|x| (*x).to_owned()).collect()))
            .collect();
        let new = NewGrant {
            grantee_kind: kind,
            grantee: who_,
            capabilities: Some(&caps),
            limits: &limits,
        };
        grants::set(&self.j.pool, &self.reg, id, &new, who())
            .await
            .unwrap();
    }

    pub async fn member(&self, id: i64, caps: &[&str], limits: &[(&str, &[&str])]) {
        self.grant(id, ("role", "member"), caps, limits).await;
    }

    pub async fn default(&self, id: i64) {
        bindings::set(&self.j.pool, id, ("workspace", ""), who())
            .await
            .unwrap();
    }

    /// A session on [`RUNNER`] of agent `bot`, allowed `allow`.
    pub async fn session(&self, allow: &[&str]) -> String {
        let s = self.bare_session(RUNNER).await;
        sqlx::query("UPDATE core_agent_sessions SET agent = 'bot' WHERE id = ?")
            .bind(&s)
            .execute(&self.j.pool)
            .await
            .unwrap();
        let list: Vec<String> = allow.iter().map(|c| (*c).to_owned()).collect();
        access::set(&self.j.pool, &s, &list).await.unwrap();
        s
    }

    /// A plain session: no agent, no access row (the default).
    pub async fn bare_session(&self, runner: &str) -> String {
        let policy = json!({});
        let new = NewSession {
            runner,
            harness: "claude",
            model: None,
            prompt: None,
            workspace: None,
            policy: &policy,
            secrets: &[],
            created_by: runner,
        };
        sessions::create(&self.j.pool, &new, AuditActor::System, NOW)
            .await
            .unwrap()
            .id
    }

    pub async fn call(&self, runner: &str, session: &str, tool: &str, args: Value) -> ToolResult {
        let call = ToolCall {
            tc_seq: 1,
            id: "c-1".to_owned(),
            tool: tool.to_owned(),
            args,
        };
        self.b.handle(&self.env(), runner, session, &call).await
    }

    /// As the session's own runner.
    pub async fn ask(&self, session: &str, tool: &str, args: Value) -> ToolResult {
        self.call(RUNNER, session, tool, args).await
    }

    pub async fn mode(&self, mode: &str) {
        crate::store::settings::set(
            &self.j.pool,
            Key::SecretsMode,
            Scope::Server,
            mode,
            AuditActor::System,
            NOW,
        )
        .await
        .unwrap();
    }

    /// Every `connection.used` row's details.
    pub async fn uses(&self) -> Vec<Value> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT details FROM audit_events WHERE action = 'connection.used' ORDER BY rowid",
        )
        .fetch_all(&self.j.pool)
        .await
        .unwrap();
        rows.iter()
            .map(|r| serde_json::from_str(r).unwrap())
            .collect()
    }

    pub async fn audit_text(&self) -> String {
        self.j.audit_text().await
    }

    pub async fn status(&self, id: i64) -> (String, Option<String>) {
        let c = crate::store::connections::get(&self.j.pool, 1, id)
            .await
            .unwrap();
        (c.status, c.state_reason)
    }
}

pub fn code(r: &ToolResult) -> &str {
    r.code.as_deref().unwrap_or("")
}

pub const ISSUE: &str = r#"{"number":7,"title":"Broken build","state":"open"}"#;
