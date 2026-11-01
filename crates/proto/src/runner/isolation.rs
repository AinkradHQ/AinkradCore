//! The isolation fields of a session's policy (E8a-08): the tier it needs, the resources it may
//! use, the destinations it may reach and how its workspace gets in. All optional; absent means
//! what a session has always had. Nothing here weakens a policy: a runner that cannot honour a
//! field refuses the session (E8a-09), it never ignores the field.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// How strongly a session is isolated from its host, weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// The harness runs as the runner's user (the default of a runner with no sandbox).
    None,
    /// A process sandbox: bubblewrap or Seatbelt.
    Process,
    /// A virtual machine with its own kernel.
    Microvm,
}

impl Isolation {
    fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Process => 1,
            Self::Microvm => 2,
        }
    }

    /// Whether a runner that offers `self` meets a session that requires `required`: a stronger
    /// tier meets a weaker requirement, never the other way round. The one place tiers compare.
    pub fn satisfies(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Process => "process",
            Self::Microvm => "microvm",
        }
    }
}

/// Destinations a session may (`allow`) or may not (`deny`) reach, as IP literals or CIDR
/// blocks. Host names are refused: they are the runner operator's, resolved only by the
/// egress proxy outside the sandbox. A session's rules can only narrow what the runner allows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Egress {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

/// How the session's workspace reaches the sandbox.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMode {
    /// The worktree is bound into the sandbox (every process tier).
    #[default]
    Bind,
    /// The worktree is copied in and the result copied out; no host path is shared (a VM).
    Copy,
}

/// Largest rule lists and entry, so a policy cannot be made to cost the runner.
const MAX_RULES: usize = 64;
const MAX_RULE_LEN: usize = 64;

pub const VCPUS: std::ops::RangeInclusive<u32> = 1..=32;
pub const MEMORY_MB: std::ops::RangeInclusive<u32> = 64..=262_144;
pub const DISK_MB: std::ops::RangeInclusive<u32> = 16..=1_048_576;
pub const WALL_SECS: std::ops::RangeInclusive<u32> = 1..=86_400;

/// `sha256:` and 64 lower-case hex digits.
pub fn digest_problem(image: &str) -> Option<&'static str> {
    let ok = image.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    (!ok).then_some("an image is sha256: and 64 lower-case hex digits")
}

/// An IP literal or `ip/prefix`; a host name does not parse.
pub fn cidr_problem(rule: &str) -> Option<&'static str> {
    if rule.is_empty() || rule.len() > MAX_RULE_LEN {
        return Some("an egress rule is an IP address or CIDR block of at most 64 characters");
    }
    let (ip, prefix) = match rule.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (rule, None),
    };
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return Some("an egress rule is an IP address or CIDR block, never a host name");
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let in_range = prefix.is_none_or(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u8>().is_ok_and(|n| n <= max)
    });
    (!in_range).then_some("an egress rule's prefix is out of range for its address family")
}

impl Egress {
    pub fn problem(&self) -> Option<String> {
        for (name, rules) in [("allow", &self.allow), ("deny", &self.deny)] {
            if rules.len() > MAX_RULES {
                return Some(format!("egress {name} has more than {MAX_RULES} rules"));
            }
            if let Some(why) = rules.iter().find_map(|r| cidr_problem(r)) {
                return Some(format!("egress {name}: {why}"));
            }
        }
        None
    }
}

#[cfg(test)]
mod skew;
#[cfg(test)]
mod tests;
