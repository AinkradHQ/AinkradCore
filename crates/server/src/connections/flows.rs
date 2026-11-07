//! Sign-in flows (C5; design §6): "Sign in with GitHub" (the device flow) and "Sign in with
//! Atlassian" (OAuth 3LO with PKCE), as live steps the UI polls. A flow is held in memory only:
//! a restart ends it and the person starts again.
//!
//! - **Server-side secrets.** The GitHub device code and the PKCE verifier never leave Core (the
//!   Jira ones stay inside `Jira`); a [`View`] holds what the screen shows: the user code and
//!   address, the Atlassian authorize address and `state`, the sites to choose from, the steps.
//! - **Owned.** A flow belongs to the user AND the device that started it; any other caller finds
//!   no such flow. It has its own id, not Jira's `state`, and a callback is accepted only when its
//!   `state` is the one this flow started with (compared in constant time), so one flow's
//!   callback cannot finish another.
//! - **Bounded.** [`MAX_PER_USER`] waiting flows per user and [`MAX_ALL`] in all; a flow ends at
//!   its code's or `state`'s expiry; a finished one is kept [`KEEP_DONE`] so the screen can read
//!   its last step.
//! - **One connection.** A flow that ends in a credential makes exactly one connection (or, when
//!   it was started for an existing one, replaces that one's credential): the tokens are sealed
//!   at once and dropped. The GitHub task polls on its own (the person may close the window);
//!   Jira finishes when the Mac app hands over `code` and `state`.
//! - **Steps**: `waiting` (the person acts in the browser), `approved` (a credential came, it is
//!   being stored and tested), `choose_site` (Jira, several sites), `connected`, `expired`,
//!   `denied`, `failed` with a plain `error`.

mod finish;
mod github;
mod jira;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ainkrad_core::audit::AuditActor;
use zeroize::Zeroizing;

pub use self::jira::{Refused, callback, choose};
use super::github::device::{DeviceError, Prompt};
use super::jira::{Finished, FlowError, Jira};
use crate::api::App;

pub const MAX_PER_USER: usize = 4;
pub const MAX_ALL: usize = 32;
/// Finished flows kept per user for the screen to read; the oldest is dropped past this.
pub const MAX_DONE: usize = 16;
pub const KEEP_DONE: Duration = Duration::from_secs(300);
const MAX_LIFE: Duration = Duration::from_secs(900);

/// A Jira site to choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteView {
    pub id: String,
    pub name: String,
    pub url: String,
}

/// What the screen shows of a flow. Nothing secret.
#[derive(Debug, Clone)]
pub struct View {
    pub id: String,
    pub kind: &'static str,
    pub step: &'static str,
    pub expires_in_secs: u64,
    /// GitHub: the code to type and where.
    pub prompt: Option<Prompt>,
    /// Jira: what the app opens, and the `state` its redirect must carry.
    pub authorize_url: Option<String>,
    pub state: Option<String>,
    pub sites: Vec<SiteView>,
    /// The connection the flow made or re-signed in.
    pub connection: Option<i64>,
    /// Who it is connected as (the last test's identity).
    pub identity: Option<String>,
    /// Plain code and sentence when the step is `failed`.
    pub error: Option<(String, String)>,
}

/// Where a flow's own work stands (never shown).
enum St {
    Waiting,
    Finishing,
    Choose(Finished),
    Done,
}

pub struct Flow {
    pub id: String,
    pub user: i64,
    pub device: String,
    pub actor: AuditActor,
    pub kind: &'static str,
    /// An existing connection this sign-in replaces the credential of.
    pub reconnect: Option<i64>,
    pub name: Option<String>,
    pub label: Option<String>,
    /// A GitHub re-sign-in may be a different account than the connection was.
    pub confirm_identity_change: bool,
    created: Instant,
    expires: Instant,
    cancelled: AtomicBool,
    /// Set under the gate once the connection is made or its credential replaced.
    committed: AtomicBool,
    /// Held while a credential is written and by a cancel, so a cancel that has returned is
    /// never followed by a connection made or a credential replaced.
    gate: tokio::sync::Mutex<()>,
    /// The Atlassian adapter holding this flow's pending sign-in (an Atlassian flow only).
    jira: Option<Arc<Jira>>,
    view: Mutex<View>,
    done_at: Mutex<Option<Instant>>,
    /// The Jira `state` this flow started with.
    jira_state: Option<Zeroizing<String>>,
    st: tokio::sync::Mutex<St>,
}

impl Drop for Flow {
    /// A flow that is removed (cancelled, expired, evicted, refused at admission) takes its
    /// pending Atlassian sign-in with it; a spent or foreign one is left alone.
    fn drop(&mut self) {
        if let (Some(jira), Some(state)) = (&self.jira, &self.jira_state) {
            jira.cancel(self.user, state);
        }
    }
}

impl Flow {
    fn set(&self, f: impl FnOnce(&mut View)) {
        let mut v = self.view.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut v);
        if matches!(v.step, "connected" | "expired" | "denied" | "failed") {
            let mut d = self.done_at.lock().unwrap_or_else(|e| e.into_inner());
            d.get_or_insert_with(Instant::now);
        }
    }

    fn step(&self) -> &'static str {
        self.view.lock().unwrap_or_else(|e| e.into_inner()).step
    }

    fn fail(&self, code: &str, message: &str) {
        self.set(|v| {
            v.step = "failed";
            v.error = Some((code.to_owned(), message.to_owned()));
        });
    }

    /// Whether this flow already made its connection (or replaced its credential).
    pub fn committed(&self) -> bool {
        self.committed.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The flow as it stands now; a flow past its end that was still waiting is `expired`.
    pub fn view(&self) -> View {
        if Instant::now() >= self.expires && matches!(self.step(), "waiting" | "choose_site") {
            self.set(|v| v.step = "expired");
        }
        let mut v = self.view.lock().unwrap_or_else(|e| e.into_inner()).clone();
        v.expires_in_secs = self
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs();
        v
    }

    /// Over: finished and kept long enough, or well past its end.
    fn stale(&self) -> bool {
        let now = Instant::now();
        let done = *self.done_at.lock().unwrap_or_else(|e| e.into_inner());
        done.is_some_and(|d| now >= d + KEEP_DONE) || now >= self.expires + KEEP_DONE
    }

    fn waiting(&self) -> bool {
        Instant::now() < self.expires
            && matches!(self.step(), "waiting" | "approved" | "choose_site")
    }
}

/// Why a flow did not start.
#[derive(Debug)]
pub enum StartError {
    /// The kind's app is not set up on this Core (the plain sentence says which).
    NotConfigured(&'static str),
    TooMany,
    Device(DeviceError),
    Jira(FlowError),
    Store(crate::store::secrets::Error),
}

impl From<crate::store::secrets::Error> for StartError {
    fn from(e: crate::store::secrets::Error) -> Self {
        Self::Store(e)
    }
}

/// What starts a flow.
pub struct Start<'a> {
    pub user: i64,
    pub device: &'a str,
    pub actor: AuditActor,
    pub kind: &'a str,
    pub reconnect: Option<i64>,
    pub name: Option<&'a str>,
    pub label: Option<&'a str>,
    pub confirm_identity_change: bool,
}

/// The flows in progress.
#[derive(Default)]
pub struct Flows {
    map: Mutex<HashMap<String, Arc<Flow>>>,
}

impl Flows {
    /// Forgets what is over: a finished flow after [`KEEP_DONE`], any flow well past its end.
    fn purge(map: &mut HashMap<String, Arc<Flow>>) {
        map.retain(|_, f| !f.stale());
    }

    fn live(map: &HashMap<String, Arc<Flow>>, user: Option<i64>) -> usize {
        let mine = |x: &&Arc<Flow>| user.is_none_or(|u| x.user == u);
        map.values().filter(mine).filter(|x| x.waiting()).count()
    }

    /// Holds `f` unless a cap is reached (a refused flow is dropped, and with it its pending
    /// sign-in). Finished flows of the user beyond [`MAX_DONE`] are dropped, oldest first. The
    /// purge runs here and nowhere else, so a read costs one lookup.
    fn admit(&self, f: Flow) -> Result<Arc<Flow>, StartError> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        Self::purge(&mut map);
        if Self::live(&map, Some(f.user)) >= MAX_PER_USER || Self::live(&map, None) >= MAX_ALL {
            return Err(StartError::TooMany);
        }
        let mut done: Vec<(Instant, String)> = map
            .values()
            .filter(|x| x.user == f.user && !x.waiting())
            .map(|x| (x.created, x.id.clone()))
            .collect();
        done.sort();
        while done.len() >= MAX_DONE {
            map.remove(&done.remove(0).1);
        }
        let f = Arc::new(f);
        map.insert(f.id.clone(), f.clone());
        Ok(f)
    }

    /// Whether `user` may start another flow now (the caps of [`Flows::admit`]), so a refused
    /// start creates nothing upstream.
    fn room(&self, user: i64) -> bool {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        Self::live(&map, Some(user)) < MAX_PER_USER && Self::live(&map, None) < MAX_ALL
    }

    /// The flow `id`, only for the user and device that started it.
    pub fn get(&self, user: i64, device: &str, id: &str) -> Option<Arc<Flow>> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(id)
            .filter(|f| f.user == user && f.device == device && !f.stale())
            .cloned()
    }

    /// Cancels and forgets flow `id` (the owner's); whether there was one. When this returns no
    /// connection will be made and no credential replaced by that flow: the flag is set under
    /// the gate a credential write holds.
    pub async fn cancel(&self, user: i64, device: &str, id: &str) -> bool {
        let Some(f) = self.get(user, device, id) else {
            return false;
        };
        {
            let _gate = f.gate.lock().await;
            f.cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(id).is_some()
    }

    /// Ends every waiting flow of `kind` (Ainkrad's app for it changed, so a code issued under
    /// the old one cannot finish): each reads `failed` with `code` and a plain sentence, and
    /// nothing it was doing is stored.
    pub async fn end(&self, kind: &str, code: &str, message: &str) {
        let flows: Vec<Arc<Flow>> = {
            let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            let hit = |f: &&Arc<Flow>| f.kind == kind && f.waiting();
            map.values().filter(hit).cloned().collect()
        };
        for f in flows {
            let _gate = f.gate.lock().await;
            // Looked at again under the gate: a flow whose connection was written meanwhile
            // (it is only being tested) is never failed, or the person would sign in twice.
            if f.committed() || !f.waiting() {
                continue;
            }
            f.cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            f.fail(code, message);
        }
    }
}

fn new_flow(
    s: &Start<'_>,
    kind: &'static str,
    life: Duration,
    view: View,
    jira: Option<(Arc<Jira>, String)>,
) -> Flow {
    let (jira, state) = jira.unzip();
    Flow {
        id: view.id.clone(),
        user: s.user,
        device: s.device.to_owned(),
        actor: s.actor,
        kind,
        reconnect: s.reconnect,
        name: s.name.map(str::to_owned),
        label: s.label.map(str::to_owned),
        confirm_identity_change: s.confirm_identity_change,
        created: Instant::now(),
        gate: tokio::sync::Mutex::new(()),
        jira,
        expires: Instant::now() + life.min(MAX_LIFE),
        cancelled: AtomicBool::new(false),
        committed: AtomicBool::new(false),
        view: Mutex::new(view),
        done_at: Mutex::new(None),
        jira_state: state.map(Zeroizing::new),
        st: tokio::sync::Mutex::new(St::Waiting),
    }
}

fn blank(kind: &'static str) -> View {
    View {
        id: crate::auth::crypto::random_id("cf_"),
        kind,
        step: "waiting",
        expires_in_secs: 0,
        prompt: None,
        authorize_url: None,
        state: None,
        sites: Vec::new(),
        connection: None,
        identity: None,
        error: None,
    }
}

/// Begins a sign-in of `s.kind`: the GitHub device flow (a task polls it) or the Atlassian
/// authorize address. The returned view is the first screen.
pub async fn start(app: &App, s: Start<'_>) -> Result<View, StartError> {
    match s.kind {
        "github" => github::start(app, s).await,
        "jira" => jira::start(app, s),
        _ => Err(StartError::NotConfigured("no sign-in for this kind")),
    }
}

fn same(a: &str, b: &str) -> bool {
    crate::auth::pairing::ct_eq(a, b)
}
