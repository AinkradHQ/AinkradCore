//! A runner's own harness histories as Brain items (E5-3). A runner the user switched on
//! (`--share-history`, off by default) answers `history.read`: it reads its harness's session
//! files, keeps only what the user and the assistant said, and sends it in parts with a cursor, so
//! the Core takes only what is new. The runner reads nothing else: a path under a restricted name
//! (keys, certificates, `.env`, contract folders) is never opened, only counted as skipped.
//!
//! A runner lists [`CAP_HISTORY_READ`] among its agent driver's commands only when it is switched
//! on; one that does not never receives the op, and an older runner or Core ignores it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The op that reads a runner's harness history.
pub const OP_HISTORY_READ: &str = "history.read";
/// The capability a runner lists when it is switched on to answer [`OP_HISTORY_READ`].
pub const CAP_HISTORY_READ: &str = "history-read";
/// The most text one answer carries.
pub const MAX_HISTORY_BYTES: u32 = 768 * 1024;
/// The most text one part carries (under the Brain's item cap).
pub const MAX_HISTORY_PART: usize = 240 * 1024;

/// Core to runner: the new entries of `harness`'s sessions after `cursor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HistoryRead {
    /// The harness whose history to read: `claude` (the others are not readable yet).
    pub harness: String,
    /// Per session id, the last entry (line) already taken.
    #[serde(default)]
    pub cursor: BTreeMap<String, u64>,
    /// The most text the answer may carry, up to [`MAX_HISTORY_BYTES`].
    pub max_bytes: u32,
}

/// One part of one session: the text said in its entries `first` to `last`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HistoryItem {
    pub session: String,
    /// The working folder the session ran in, as the harness recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Where it came from, relative to the harness's history folder.
    pub path: String,
    pub title: String,
    /// `User: ...` and `Assistant: ...` blocks, redacted by the runner.
    pub text: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    pub first: u64,
    pub last: u64,
}

/// What was not read, and why (`restricted_path`, `unreadable`, `no_time`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HistorySkip {
    pub reason: String,
    pub count: u64,
}

/// Runner to Core: the new parts, the cursor after them (only sessions that moved), what was
/// skipped, and whether more waits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HistoryChunk {
    pub items: Vec<HistoryItem>,
    pub cursor: BTreeMap<String, u64>,
    #[serde(default)]
    pub skipped: Vec<HistorySkip>,
    pub more: bool,
}

/// Files and folders whose content is never read (Q-18): keys, certificates, `.env`, key stores,
/// contract folders. The Brain applies the same rule to what it receives
/// (`brain_model::rules::restricted_path`); a test there keeps the two equal.
pub fn restricted_path(path: &str) -> bool {
    const EXT: &[&str] = &[
        "pem", "p8", "p12", "pfx", "key", "crt", "cer", "jks", "keystore", "kdbx", "ppk",
    ];
    const NAMES: &[&str] = &[
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        ".npmrc",
        ".netrc",
        "credentials",
    ];
    const DIRS: &[&str] = &["contracts", "contract", "agreements", "nda"];
    let lower = path.to_lowercase();
    let parts: Vec<&str> = lower.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    let Some(file) = parts.last() else {
        return false;
    };
    file == &".env"
        || file.starts_with(".env.")
        || NAMES.contains(file)
        || file.rsplit_once('.').is_some_and(|(_, e)| EXT.contains(&e))
        || parts[..parts.len() - 1].iter().any(|d| DIRS.contains(d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{Command, Reply};

    #[test]
    fn the_op_and_its_answer_round_trip_under_their_wire_names() {
        let read = HistoryRead {
            harness: "claude".to_owned(),
            cursor: BTreeMap::from([("s1".to_owned(), 7)]),
            max_bytes: 1000,
        };
        let cmd = Command::HistoryRead(read.clone());
        assert_eq!(cmd.op(), OP_HISTORY_READ);
        let json = serde_json::to_value(&cmd).unwrap();
        assert_eq!(json["op"], "history.read");
        assert_eq!(serde_json::from_value::<Command>(json).unwrap(), cmd);
        let chunk = HistoryChunk {
            items: vec![],
            cursor: read.cursor,
            skipped: vec![],
            more: true,
        };
        let reply = Reply::HistoryRead(chunk);
        let json = serde_json::to_value(&reply).unwrap();
        assert_eq!(json["op"], "history.read");
        assert_eq!(serde_json::from_value::<Reply>(json).unwrap(), reply);
    }

    #[test]
    fn keys_env_files_and_contract_folders_are_restricted() {
        for p in [
            "/a/.env",
            "/a/.env.prod",
            "/a/k.pem",
            "/a/id_rsa",
            "/a/contracts/x.md",
            "/a/NDA/x",
        ] {
            assert!(restricted_path(p), "{p}");
        }
        for p in [
            "/a/src/main.rs",
            "/a/contracts",
            "claude/-Users-x-Projects-Alpha/s.jsonl",
        ] {
            assert!(!restricted_path(p), "{p}");
        }
    }
}
