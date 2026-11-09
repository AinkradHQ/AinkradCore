//! The bodies of the connection routes. A credential is written, never read: the request types
//! that carry one have no `Debug`, and no response type has a field for one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::api::v1::types::Timestamp;

/// One way to sign in to a kind, easiest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct KindAuthMethod {
    /// `oauth` (the kind's own sign-in), `app_install` (a GitHub App installation) or `token`.
    pub id: String,
    pub title: String,
    /// A plain sentence for the screen.
    pub help: String,
    /// The steps the screen shows, in order.
    pub steps: Vec<String>,
    /// Shown under "Advanced", not as the first choice.
    pub advanced: bool,
    /// `false` while the Core lacks what the method needs (Ainkrad's app is not set up yet, an
    /// admin enters it with `setConnectionApp`): the screen says "not set up yet".
    pub available: bool,
}

/// A named permission of a kind.
#[derive(Debug, Serialize, ToSchema)]
pub struct KindCapability {
    pub name: String,
    /// A plain label.
    pub title: String,
    /// `read` or `write`: a write capability is only ever granted by naming it.
    pub class: String,
    pub write: bool,
}

/// A key of the resource limit a grant may carry.
#[derive(Debug, Serialize, ToSchema)]
pub struct KindLimit {
    /// `repos` (GitHub), `projects` (Jira).
    pub key: String,
    pub title: String,
    pub help: String,
}

/// What a screen draws a kind's setup from.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionKind {
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub auth_methods: Vec<KindAuthMethod>,
    pub capabilities: Vec<KindCapability>,
    pub limits: Vec<KindLimit>,
    /// Whether Sign in works: Ainkrad's app for the kind is set up on this Core.
    pub configured: bool,
    /// GitHub: where the person installs the GitHub App to choose repositories, when it is set up.
    pub install_url: Option<String>,
}

/// What someone may do with a connection.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionGrant {
    /// `user` (a user id), `role` (`admin`, `member`) or `agent` (an agent id).
    pub grantee_kind: String,
    pub grantee: String,
    pub capabilities: Vec<String>,
    /// The resources it reaches, by the kind's limit key; none: any.
    pub limits: BTreeMap<String, Vec<String>>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// A connection: never its credential.
#[derive(Debug, Serialize, ToSchema)]
pub struct Connection {
    pub id: i64,
    /// `github` or `jira`.
    pub kind: String,
    pub name: String,
    pub label: String,
    /// The account or site the last test read (a GitHub login, an Atlassian account at a site).
    pub identity: Option<String>,
    pub auth_method: String,
    /// `active`, `cooling`, `limited`, `unhealthy` or `disabled`.
    pub status: String,
    /// A fixed code: `rate_limited`, `quota`, `upstream_errors`, `auth_suspected`, `auth_failed`,
    /// `exported`.
    pub state_reason: Option<String>,
    pub state_until: Option<Timestamp>,
    pub last_tested_at: Option<Timestamp>,
    /// When the access token ends, when known.
    pub expires_at: Option<Timestamp>,
    /// The admin's own off switch.
    pub disabled: bool,
    /// The kind's default connection: used when several cover a call.
    pub is_default: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// `admin` devices: the device that made it.
    pub created_by: Option<String>,
    /// `admin` devices: how many grants say who may use it.
    pub grant_count: Option<i64>,
    /// Other devices: what the caller may do with it (the capabilities of the grants that name
    /// the caller); never anyone else's grants or limits.
    pub my_capabilities: Option<Vec<String>>,
}

/// A connection to make with a pasted credential (the Advanced way) or a GitHub App
/// installation. No `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct NewConnection {
    pub kind: String,
    /// `[a-z][a-z0-9._-]{0,63}`, unique per kind; absent, `<kind>-<n>`.
    pub name: Option<String>,
    /// What people see, 1 to 80 characters; absent, the kind's title.
    pub label: Option<String>,
    /// `token` or `app_install`.
    pub auth_method: String,
    /// The token or API token; written, never read back.
    #[schema(value_type = Option<String>)]
    pub token: Option<Zeroizing<String>>,
    /// Jira token: the Atlassian account email.
    pub email: Option<String>,
    /// Jira token: the site, `acme.atlassian.net`.
    pub site: Option<String>,
    /// `app_install`: the GitHub App installation id the setup page returned.
    pub installation_id: Option<i64>,
}

/// A replacement credential; the same fields as [`NewConnection`]'s. No `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct NewConnectionCredential {
    #[schema(value_type = Option<String>)]
    pub token: Option<Zeroizing<String>>,
    pub email: Option<String>,
    pub site: Option<String>,
    pub installation_id: Option<i64>,
}

/// What to change about a connection; at least one field.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateConnection {
    pub name: Option<String>,
    pub label: Option<String>,
    /// The admin's off switch.
    pub disabled: Option<bool>,
}

/// Who may use a connection and how far; replaces that grantee's grant.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetConnectionGrant {
    /// `user`, `role` or `agent`.
    pub grantee_kind: String,
    pub grantee: String,
    /// Capability names of the kind; absent, its read-only ones. Never `*`: a write capability
    /// is named.
    pub capabilities: Option<Vec<String>>,
    /// Resource limits by the kind's limit key (`repos`: `owner/name` or `owner/*`; `projects`:
    /// keys); absent or empty, any resource.
    pub limits: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DefaultConnection {
    pub kind: String,
    /// The connection used when several of the kind cover a call.
    pub connection: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetDefaultConnection {
    pub connection: i64,
}

/// A use of a connection, from its audit rows: no payload.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionUse {
    /// The audit row's number: page with `before`.
    pub seq: i64,
    pub at: Timestamp,
    pub kind: Option<String>,
    /// The operation, `github.get_issue`.
    pub action: Option<String>,
    /// `ok`, `refused` or `error`.
    pub result: Option<String>,
    /// The refusal code or the upstream class.
    pub code: Option<String>,
    pub session: Option<String>,
    pub agent: Option<String>,
}

/// A sign-in to start.
#[derive(Debug, Deserialize, ToSchema)]
pub struct StartConnectionFlow {
    /// `github` or `jira`.
    pub kind: String,
    /// Names the connection it makes; absent, `<kind>-<n>`.
    pub name: Option<String>,
    pub label: Option<String>,
    /// Sign in again for this connection: its credential is replaced, nothing else changes.
    pub connection: Option<i64>,
    /// With `connection` on GitHub: replace the credential even when the sign-in is a different
    /// GitHub account than the connection's. Without it that is refused (`different_account`).
    pub confirm_identity_change: Option<bool>,
}

/// One Jira site to choose.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionFlowSite {
    /// The Atlassian cloud id: what `chooseConnectionSite` takes.
    pub id: String,
    pub name: String,
    pub url: String,
}

/// A sign-in as it stands: poll it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionFlow {
    /// `cf_…`, the flow's own id.
    pub id: String,
    pub kind: String,
    /// `waiting`, `approved`, `choose_site`, `connected`, `expired`, `denied` or `failed`.
    pub step: String,
    pub expires_in_secs: i64,
    /// GitHub: the code to type, large.
    pub user_code: Option<String>,
    /// GitHub: the address to open.
    pub verification_uri: Option<String>,
    /// GitHub: seconds between polls.
    pub interval: Option<i64>,
    /// Atlassian: what the Mac app opens in the browser.
    pub authorize_url: Option<String>,
    /// Atlassian: the `state` the redirect must carry; hand it back with the `code`.
    pub state: Option<String>,
    /// Atlassian, `choose_site`: the sites to pick from.
    pub sites: Vec<ConnectionFlowSite>,
    /// Once `connected`: the connection.
    pub connection: Option<i64>,
    /// Once `connected`: who it is connected as.
    pub identity: Option<String>,
    /// When `failed`: a fixed code and a plain sentence with the fix.
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

/// What the Mac app's loopback listener received. No `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct ConnectionFlowCallback {
    #[schema(value_type = String)]
    pub code: Zeroizing<String>,
    pub state: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConnectionFlowChoice {
    /// A site's `id` from the flow.
    pub site: String,
}

/// One field of an app's config.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionAppField {
    pub name: String,
    pub title: String,
    /// A secret is write-only: only `set` is ever said.
    pub secret: bool,
    pub set: bool,
    /// The value of a field that is no secret.
    pub value: Option<String>,
}

/// Ainkrad's OAuth app for a kind, as configured: never a secret.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionApp {
    pub kind: String,
    /// Sign in works for the kind.
    pub configured: bool,
    /// GitHub: the GitHub App (repositories) is set up.
    pub app_install_configured: bool,
    pub fields: Vec<ConnectionAppField>,
    /// Atlassian: the redirect address to register with Atlassian, exactly.
    pub redirect_uri: Option<String>,
}

/// Fields to set (`"name": "value"`) or clear (`"name": null`). No `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct SetConnectionApp {
    #[schema(value_type = BTreeMap<String, Option<String>>)]
    pub fields: BTreeMap<String, Option<Zeroizing<String>>>,
}
