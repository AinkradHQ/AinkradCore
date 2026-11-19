//! Subscription sign-in ops (KAN-441 L1/L2; plan `2026-11-05-claude-subscription-sign-in`): a
//! one-shot vendor-CLI login on a runner (design §11b.8), never on the Core host.
//!
//! - `login.start` makes the runner run the harness's own sign-in in a PTY and answers
//!   [`LoginUrl`] (`login.url`) once it has the sign-in URL, or an error.
//! - `login.code` hands the approval code the user pasted to that PTY and answers
//!   [`LoginResult`] (`login.result`): the token, once, or why there is none.
//! - `login.cancel` ends the sign-in and answers a `login.result` with an error.
//!
//! A runner that can run a sign-in lists [`CAP_LOGIN`] among its agent driver's commands. The
//! token and the code are secrets: neither type has a `Debug` that shows them, and nothing
//! streams the PTY to any client.

use serde::{Deserialize, Serialize};

pub const OP_LOGIN_START: &str = "login.start";
pub const OP_LOGIN_CODE: &str = "login.code";
pub const OP_LOGIN_CANCEL: &str = "login.cancel";
/// Core to runner: wait for a runner-bound sign-in (no code to type) to finish.
pub const OP_LOGIN_WAIT: &str = "login.wait";

/// The command an agent driver lists when its runner can run a subscription sign-in.
pub const CAP_LOGIN: &str = "login";
/// Prefix of the command a runner lists for each harness whose login it can run bound to itself
/// (`login-bound:codex`): the credential stays in that runner's own home for the account.
pub const CAP_LOGIN_BOUND: &str = "login-bound:";

/// Core to runner: begin the sign-in of `harness` (`claude`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginStart {
    pub login_id: String,
    pub harness: String,
    /// A runner-bound sign-in (E7-4/5/5b): the key of the account home the runner logs in to
    /// (`[A-Za-z0-9_-]{1,64}`, a dir of the runner's own). The credential never leaves it. Absent
    /// is the Claude sign-in, whose token comes back once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
}

/// Core to runner: wait for the runner-bound sign-in `login_id` to finish; answered by a
/// `login.result` with `done` set, or an error. No code is typed and no token comes back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginWait {
    pub login_id: String,
}

/// Core to runner: the approval code the user pasted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginCode {
    pub login_id: String,
    pub code: String,
}

/// Core to runner: stop the sign-in and wipe what it made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginCancel {
    pub login_id: String,
}

/// Runner to Core, the answer to `login.start`: where the user signs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginUrl {
    pub login_id: String,
    pub url: String,
    /// The one-time device code the user types on that page (Codex). Not a credential: it is
    /// shown to the user and is useless once the sign-in ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Runner to Core, the answer to `login.code` and `login.cancel`: the token (once; the runner
/// zeroizes its copy) or an error, never both.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginResult {
    pub login_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// A runner-bound sign-in finished: the credential is in the account's home on the runner.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub done: bool,
}

impl std::fmt::Debug for LoginCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginCode")
            .field("login_id", &self.login_id)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LoginResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginResult")
            .field("login_id", &self.login_id)
            .field("has_token", &self.token.is_some())
            .finish_non_exhaustive()
    }
}
