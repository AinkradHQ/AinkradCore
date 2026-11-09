//! Provider accounts (E15.1, decision #41): one pool owned by the admin, each account assigned
//! to the companies that may use it, usage attributed per company. An account names where its
//! secret lives on a runner host (`credential_ref`), never the secret.

use std::str::FromStr;

use super::Billing;
use crate::org::{Harness, UnknownVariant, id, text_enum};

id!(AccountId);

// `limited`: at a usage limit until its window rolls (E15.2); `unhealthy`: dropped too often
// (E15.4); `disabled`: by the admin. Only `active` accounts get runs.
text_enum!(AccountStatus {
    Active => "active",
    Limited => "limited",
    Unhealthy => "unhealthy",
    Disabled => "disabled",
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccount {
    pub harness: Harness,
    /// Unique, `[a-z0-9][a-z0-9._-]*`, e.g. `claude-work`.
    pub label: String,
    /// The file holding the token, relative to a runner's credentials dir; `None` when the
    /// account's config dir holds a login instead.
    pub credential_ref: Option<String>,
    /// The variable the harness reads the token from (one of the harness's auth variables).
    pub credential_env: Option<String>,
    /// The harness's config dir for this account, relative to a runner's config root.
    pub config_dir: String,
    pub billing: Billing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub harness: Harness,
    pub label: String,
    pub credential_ref: Option<String>,
    pub credential_env: Option<String>,
    pub config_dir: String,
    pub billing: Billing,
    pub status: AccountStatus,
    /// Why it is not `active`.
    pub status_reason: Option<String>,
    /// When a `limited` or `unhealthy` status ends by itself, if the server knows (E15.2).
    pub status_until: Option<String>,
    pub last_used_at: Option<String>,
    /// Companies it is assigned to, by id.
    pub companies: Vec<i64>,
    /// Its plan tier as the admin wrote it (`Max 20x`, `Pro`); shown, never enforced.
    pub plan_tier: Option<String>,
}

/// Whether `label` is a plain account label.
pub fn account_label_ok(label: &str) -> bool {
    let mut bytes = label.bytes();
    label.len() <= 64
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

// What a usage limit counts (E15.2): every token of the account's cost events, or every prompt
// sent as it.
text_enum!(LimitUnit {
    Tokens => "tokens",
    Messages => "messages",
});

/// A usage limit of an account over a rolling window, e.g. 5 h of messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLimit {
    pub id: i64,
    pub account_id: AccountId,
    pub window_secs: i64,
    pub unit: LimitUnit,
    pub max: i64,
    /// The admin is warned once per window at this share of `max`.
    pub warn_percent: i64,
}

/// A limit before it is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewAccountLimit {
    pub window_secs: i64,
    pub unit: LimitUnit,
    pub max: i64,
    /// `None`: the account's `account.warn_percent` setting (E15.17).
    pub warn_percent: Option<i64>,
}

/// `5h`, `7d`, `30m` or `90s` in seconds; `None` for anything else or zero.
pub fn window_secs(text: &str) -> Option<i64> {
    let (split, _) = text.char_indices().last()?;
    let (n, unit) = text.split_at(split);
    let n: i64 = n.parse().ok().filter(|n| *n > 0)?;
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    n.checked_mul(scale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_parse_from_short_text() {
        assert_eq!(window_secs("5h"), Some(18_000));
        assert_eq!(window_secs("7d"), Some(604_800));
        assert_eq!(window_secs("30m"), Some(1800));
        assert_eq!(window_secs("90s"), Some(90));
        for bad in ["", "h", "0h", "-1h", "5", "5w", "1.5h", "5é"] {
            assert_eq!(window_secs(bad), None, "{bad}");
        }
        assert!(account_label_ok("claude-1") && !account_label_ok("-x"));
    }
}
