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

/// The command an agent driver lists when its runner can run a subscription sign-in.
pub const CAP_LOGIN: &str = "login";

/// Core to runner: begin the sign-in of `harness` (`claude`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoginStart {
    pub login_id: String,
    pub harness: String,
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
