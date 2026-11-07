//! Ainkrad's OAuth apps, as the API configures them (C5; design §6, decision 1). The strings are
//! sealed in `store::connections::apps`; this module says which fields a kind has, checks a value,
//! and puts a config into force WITHOUT making a second adapter: Atlassian's client id, secret and
//! redirect go into the one shared `Jira` ([`Jira::set_app`]); GitHub's client id is held here and
//! the GitHub App's key goes to the one shared `Github`'s installer.
//!
//! The config belongs to the Core, not to a user: it is kept under the admin user (`OWNER`, #18).

use std::collections::BTreeMap;
use std::sync::RwLock;

use serde::Serialize;
use zeroize::Zeroizing;

use super::github::Github;
use super::github::app::AppKey;
use super::jira::{Jira, OAuthApp};
use crate::ops::secretbox::SecretBox;
use crate::store::connections::apps;
use crate::store::secrets::Error;

/// The user whose rows hold the Core's app config.
pub const OWNER: i64 = 1;
/// The loopback port the Mac app's catcher listens on (registered with Atlassian), unless set.
pub const DEFAULT_PORT: u16 = 47613;

/// One field of an app's config.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Field {
    pub name: &'static str,
    pub title: &'static str,
    /// Write-only: never returned, not even its length.
    pub secret: bool,
}

pub const GITHUB_FIELDS: &[Field] = &[
    Field {
        name: "client_id",
        title: "GitHub OAuth app client id (Device Flow enabled)",
        secret: false,
    },
    Field {
        name: "app_id",
        title: "GitHub App id",
        secret: false,
    },
    Field {
        name: "app_slug",
        title: "GitHub App name in its URL",
        secret: false,
    },
    Field {
        name: "app_key",
        title: "GitHub App private key (PEM)",
        secret: true,
    },
];

pub const JIRA_FIELDS: &[Field] = &[
    Field {
        name: "client_id",
        title: "Atlassian OAuth app client id",
        secret: false,
    },
    Field {
        name: "client_secret",
        title: "Atlassian OAuth app secret",
        secret: true,
    },
    Field {
        name: "loopback_port",
        title: "Port of the Mac app's sign-in catcher on 127.0.0.1 (registered with Atlassian)",
        secret: false,
    },
];

/// The fields of `kind`; `None` for a kind with no app config.
pub fn fields(kind: &str) -> Option<&'static [Field]> {
    match kind {
        "github" => Some(GITHUB_FIELDS),
        "jira" => Some(JIRA_FIELDS),
        _ => None,
    }
}

fn plain(s: &str, max: usize, extra: &[u8]) -> bool {
    (1..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// Why `value` is not one for `kind`'s `field`, if it is not. The private key is checked by
/// parsing it; it needs the App's id, so a write of the key says which id it goes with.
pub fn problem(kind: &str, field: &str, value: &str) -> Option<&'static str> {
    let ok = match (kind, field) {
        (_, "client_id") => plain(value, 64, b"._-"),
        ("jira", "client_secret") => {
            (1..=512).contains(&value.len()) && !value.chars().any(char::is_control)
        }
        ("jira", "loopback_port") => value.parse::<u16>().is_ok_and(|p| p >= 1024),
        ("github", "app_id") => plain(value, 40, b"_-"),
        ("github", "app_slug") => plain(value, 64, b"-"),
        ("github", "app_key") => {
            value.len() <= apps::MAX_FIELD_BYTES && AppKey::new("1", value).is_some()
        }
        _ => return Some("no such field"),
    };
    (!ok).then_some("that value is not valid for the field")
}

/// What is in force now, set from the sealed config: GitHub's client id, and whether each app
/// is usable. The Jira app and the GitHub App key live in their adapters.
#[derive(Default)]
pub struct Apps {
    github_client_id: RwLock<Option<Zeroizing<String>>>,
    github_slug: RwLock<Option<String>>,
}

impl Apps {
    /// The device flow's client id, when set.
    pub fn github_client_id(&self) -> Option<String> {
        let held = self
            .github_client_id
            .read()
            .unwrap_or_else(|e| e.into_inner());
        held.as_ref().map(|c| c.to_string())
    }

    /// The GitHub App's name in its URL (`github.com/apps/<slug>/installations/new`), when set.
    pub fn github_slug(&self) -> Option<String> {
        self.github_slug
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The redirect the Mac app's catcher uses for `port`.
    pub fn redirect(port: u16) -> String {
        format!("http://127.0.0.1:{port}/callback")
    }

    /// Reads the sealed config and puts it into force: the ONE shared `jira` gets (or loses) its
    /// OAuth app, the ONE shared `github` its App key. Called at start and after every config
    /// write. A kind whose config is incomplete or does not parse is simply off.
    pub async fn reload(
        &self,
        pool: &sqlx::sqlite::SqlitePool,
        sealer: &SecretBox,
        jira: &Jira,
        github: &Github,
    ) -> Result<(), Error> {
        let g = apps::open_all(pool, sealer, OWNER, "github").await?;
        let j = apps::open_all(pool, sealer, OWNER, "jira").await?;
        *self
            .github_client_id
            .write()
            .unwrap_or_else(|e| e.into_inner()) = g.get("client_id").cloned();
        *self.github_slug.write().unwrap_or_else(|e| e.into_inner()) =
            g.get("app_slug").map(|s| s.to_string());
        github.installer().set_key(app_key(&g));
        jira.set_app(jira_app(&j));
        Ok(())
    }
}

fn app_key(g: &BTreeMap<String, Zeroizing<String>>) -> Option<AppKey> {
    AppKey::new(g.get("app_id")?, g.get("app_key")?)
}

fn jira_app(j: &BTreeMap<String, Zeroizing<String>>) -> Option<OAuthApp> {
    let port = j
        .get("loopback_port")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let redirect = Apps::redirect(port);
    OAuthApp::new(j.get("client_id")?, j.get("client_secret")?, &[&redirect])
}

/// Puts the sealed config into force for `app`'s shared adapters (at start, and after a write).
/// Nothing to do without a master key.
pub async fn reload(app: &crate::api::App) -> Result<(), Error> {
    let Some(sealer) = app.secrets.as_ref() else {
        return Ok(());
    };
    app.conn_apps
        .reload(
            &app.pool,
            sealer,
            app.connections.jira(),
            app.connections.github(),
        )
        .await
}
