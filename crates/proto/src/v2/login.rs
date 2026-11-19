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
/// Core to runner: type one line into a runner-bound sign-in (the guided terminal, E7-5).
pub const OP_LOGIN_INPUT: &str = "login.input";
/// Core to runner: read the redacted screen of a runner-bound sign-in (the guided terminal).
pub const OP_LOGIN_SCREEN: &str = "login.screen";
/// Core to runner: delete a runner-bound account's login (its home dir) from the runner.
pub const OP_LOGIN_WIPE: &str = "login.wipe";
/// The most a typed line may be.
pub const LOGIN_INPUT_MAX: usize = 512;

/// The command an agent driver lists when its runner can run a subscription sign-in.
pub const CAP_LOGIN: &str = "login";
/// Prefix of the command a runner lists for each harness whose login it can run bound to itself
/// (`login-bound:codex`): the credential stays in that runner's own home for the account.
pub const CAP_LOGIN_BOUND: &str = "login-bound:";
/// The command a runner lists when it can wipe a bound account's home (`login.wipe`).
pub const CAP_LOGIN_WIPE: &str = "login-wipe";

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

/// Core to runner: one line the user typed into a guided sign-in (a pasted code, or a menu choice),
/// sent with Enter. A secret: no `Debug` that shows it, never stored, never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginInput {
    pub login_id: String,
    pub text: String,
}

impl std::fmt::Debug for LoginInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginInput")
            .field("login_id", &self.login_id)
            .finish_non_exhaustive()
    }
}

/// Core to runner: delete the home of a removed runner-bound account. The runner checks the key
/// (`bound_key_ok`), touches only `<agents-config>/bound/<home>`, refuses a symlink there, and answers
/// a `login.result` with `done` set (also when there was nothing to delete), or an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginWipe {
    /// The account's home key (`[A-Za-z0-9_-]{1,64}`).
    pub home: String,
}

/// Core to runner: the current screen of the sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginScreenReq {
    pub login_id: String,
}

/// Runner to Core, the answer to `login.screen`: what the CLI shows, after the redactor and cut to
/// the last lines. Text only; nothing but a typed line ever goes back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginScreen {
    pub login_id: String,
    pub lines: Vec<String>,
    /// The sign-in page the CLI printed, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A device code the CLI printed, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
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
