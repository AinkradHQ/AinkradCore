//! Ainkrad's OAuth apps, as the API configures them (C5; design §6, decision 1). The strings are
//! sealed in `store::connections::apps`; this module says which fields a kind has, checks a value,
//! and puts a config into force WITHOUT making a second adapter: Atlassian's client id, secret and
//! redirect go into the one shared `Jira` (`Jira::set_app`), Linear's into the one shared
//! `Linear` (`Linear::set_app`), Slack's into the one shared `Slack` (`Slack::set_app`),
//! Microsoft's client id and tenant into the one shared `Teams` (`Teams::set_app`); GitHub's
//! client id is held here and
//! the GitHub App's key goes to the one shared `Github`'s installer.
//!
//! The config belongs to the Core, not to a user: it is kept under the admin user (`OWNER`, #18).

use std::collections::BTreeMap;
use std::sync::RwLock;

use serde::Serialize;
use zeroize::Zeroizing;

use super::broker::Broker;
use super::github::app::AppKey;
use super::jira::OAuthApp;
use super::linear::OAuthApp as LinearApp;
use super::slack::SlackApp;
use super::teams::TeamsApp;
use crate::ops::secretbox::SecretBox;
use crate::store::connections::apps;
use crate::store::secrets::Error;

/// The user whose rows hold the Core's app config.
pub const OWNER: i64 = 1;
/// Ainkrad's own public GitHub OAuth app (device flow: no secret exists). A Core uses it when the
/// database holds no GitHub app of its own, so a user only connects (N23); an admin can still
/// replace it by writing the `github` app config.
pub const BUILT_IN_GITHUB_CLIENT_ID: &str = "Ov23litUTAjReYNz80Fy";
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

/// Slack's redirect is an `https` address of Ainkrad's or of this Core (Slack refuses a loopback
/// `http` one); its own field, registered with Slack exactly.
pub const SLACK_FIELDS: &[Field] = &[
    Field {
        name: "client_id",
        title: "Slack app client id",
        secret: false,
    },
    Field {
        name: "client_secret",
        title: "Slack app client secret",
        secret: true,
    },
    Field {
        name: "redirect_uri",
        title: "https redirect URL registered with Slack (where code and state are caught)",
        secret: false,
    },
    Field {
        name: "catcher_ready",
        title: "true once a page at that https address hands code and state to Core",
        secret: false,
    },
    Field {
        name: "token_rotation",
        title: "true if the Slack app has token rotation on (needs secrets.mode 2)",
        secret: false,
    },
];

/// Microsoft's app is a PUBLIC client (the device code flow): a client id and a tenant, no secret.
/// `tenant` is `organizations` (any work or school tenant; the default) or one tenant's GUID.
pub const TEAMS_FIELDS: &[Field] = &[
    Field {
        name: "client_id",
        title: "Microsoft app (client) id",
        secret: false,
    },
    Field {
        name: "tenant",
        title: "Tenant: organizations, or one tenant's id (a GUID)",
        secret: false,
    },
];

pub const LINEAR_FIELDS: &[Field] = &[
    Field {
        name: "client_id",
        title: "Linear OAuth app client id",
        secret: false,
    },
    Field {
        name: "client_secret",
        title: "Linear OAuth app client secret",
        secret: true,
    },
    Field {
        name: "loopback_port",
        title: "Port of the Mac app's sign-in catcher on 127.0.0.1 (registered with Linear)",
        secret: false,
    },
];

/// The fields of `kind`; `None` for a kind with no app config.
pub fn fields(kind: &str) -> Option<&'static [Field]> {
    match kind {
        "github" => Some(GITHUB_FIELDS),
        "jira" => Some(JIRA_FIELDS),
        "linear" => Some(LINEAR_FIELDS),
        "slack" => Some(SLACK_FIELDS),
        "teams" => Some(TEAMS_FIELDS),
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
        ("jira" | "linear" | "slack", "client_secret") => {
            (1..=512).contains(&value.len()) && !value.chars().any(char::is_control)
        }
        ("jira" | "linear", "loopback_port") => value.parse::<u16>().is_ok_and(|p| p >= 1024),
        ("slack", "redirect_uri") => super::slack::redirect_ok(value),
        ("slack", "catcher_ready" | "token_rotation") => matches!(value, "true" | "false"),
        ("teams", "tenant") => value == "organizations" || super::teams::tenant_id(value),
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
    /// The device flow's client id: the admin's own app when one is set, else Ainkrad's built-in
    /// one. Always `Some`.
    pub fn github_client_id(&self) -> Option<String> {
        let held = self
            .github_client_id
            .read()
            .unwrap_or_else(|e| e.into_inner());
        Some(
            held.as_ref()
                .map_or_else(|| BUILT_IN_GITHUB_CLIENT_ID.to_owned(), |c| c.to_string()),
        )
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
        adapters: &Broker,
    ) -> Result<Changed, Error> {
        let (jira, github, linear) = (adapters.jira(), adapters.github(), adapters.linear());
        let (slack, teams) = (adapters.slack(), adapters.teams());
        let g = apps::open_all(pool, sealer, OWNER, "github").await?;
        let j = apps::open_all(pool, sealer, OWNER, "jira").await?;
        let l = apps::open_all(pool, sealer, OWNER, "linear").await?;
        let s = apps::open_all(pool, sealer, OWNER, "slack").await?;
        let t = apps::open_all(pool, sealer, OWNER, "teams").await?;
        let client = g.get("client_id").cloned();
        let github_changed = {
            let mut held = self
                .github_client_id
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let same = held.as_ref().map(|c| c.as_str()) == client.as_ref().map(|c| c.as_str());
            *held = client;
            !same
        };
        *self.github_slug.write().unwrap_or_else(|e| e.into_inner()) =
            g.get("app_slug").map(|s| s.to_string());
        github.installer().set_key(app_key(&g));
        let jira_changed = jira.set_app(jira_app(&j));
        let linear_changed = linear.set_app(linear_app(&l));
        let slack_changed = slack.set_app(slack_app(&s));
        let teams_changed = teams.set_app(teams_app(&t));
        Ok(Changed {
            github: github_changed,
            jira: jira_changed,
            linear: linear_changed,
            slack: slack_changed,
            teams: teams_changed,
        })
    }
}

/// Which kinds' sign-in apps a reload actually changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Changed {
    pub github: bool,
    pub jira: bool,
    pub linear: bool,
    pub slack: bool,
    pub teams: bool,
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

/// The Slack app in force. Add to Slack signs in only when the https redirect page exists
/// (`catcher_ready`) and a valid https redirect is set: no page, no sign-in, and the UI shows the
/// bot token as the working method. The client id and secret alone stay in force either way, so
/// the tokens already issued keep being renewed.
fn slack_app(s: &BTreeMap<String, Zeroizing<String>>) -> Option<SlackApp> {
    let flag = |k: &str| s.get(k).is_some_and(|v| v.as_str() == "true");
    let (id, secret) = (s.get("client_id")?, s.get("client_secret")?);
    let signing_in = flag("catcher_ready")
        .then(|| s.get("redirect_uri"))
        .flatten()
        .and_then(|r| SlackApp::new(id, secret, r));
    let app = signing_in.or_else(|| SlackApp::renewal_only(id, secret))?;
    Some(app.rotating(flag("token_rotation")))
}

fn teams_app(t: &BTreeMap<String, Zeroizing<String>>) -> Option<TeamsApp> {
    let tenant = t.get("tenant").map_or("organizations", |s| s.as_str());
    TeamsApp::new(t.get("client_id")?, tenant)
}

fn linear_app(l: &BTreeMap<String, Zeroizing<String>>) -> Option<LinearApp> {
    let port = l
        .get("loopback_port")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let redirect = Apps::redirect(port);
    LinearApp::new(l.get("client_id")?, l.get("client_secret")?, &[&redirect])
}

/// Puts the sealed config into force for `app`'s shared adapters (at start, and after a write).
/// Nothing to do without a master key.
pub async fn reload(app: &crate::api::App) -> Result<(), Error> {
    let Some(sealer) = app.secrets.as_ref() else {
        return Ok(());
    };
    let changed = app
        .conn_apps
        .reload(&app.pool, sealer, &app.connections)
        .await?;
    // A sign-in begun under an app that changed cannot finish; one of a kind that did not change
    // goes on.
    let why = "Ainkrad's sign-in app for this service changed; start the sign-in again";
    for (kind, hit) in [
        ("github", changed.github),
        ("jira", changed.jira),
        ("linear", changed.linear),
        ("slack", changed.slack),
        ("teams", changed.teams),
    ] {
        if hit {
            app.conn_flows.end(kind, "app_changed", why).await;
        }
    }
    Ok(())
}
