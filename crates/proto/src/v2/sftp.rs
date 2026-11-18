//! SFTP ops of the `ssh` driver (Leyline Y2-03, plan T5): list, stat, read, write, mkdir, rename and
//! remove on a remote host, over the same dial, pins and key leases as `ssh.exec`.
//!
//! Every path is data: it goes into an SFTP packet as given and is never read by a shell (there is
//! none), so `../x`, a newline or a leading `-` are only names. The one refusal is a NUL byte.
//!
//! **Bytes reuse the terminal framing** (`terminal.rs`): on `ssh.sftp.read` the runner sends `output`
//! frames (standard base64) and may send [`STREAM_WINDOW`](super::STREAM_WINDOW) decoded bytes before
//! the Core grants more with `credit`; the answer is a `result` with the byte count. On
//! `ssh.sftp.write` the directions swap: the Core sends `output` frames within the credit the runner
//! grants (it starts with one window, and grants back as it writes), then `control` `eof`; the
//! answer is the `result`. A Core `close` cancels either: a write then leaves nothing behind on the
//! host (the data goes to a temporary file beside the target, renamed into place only after `eof`).
//! One transfer carries at most [`SFTP_MAX_BYTES`].

use serde::{Deserialize, Serialize};

use super::SshHop;

pub const OP_SFTP_LIST: &str = "ssh.sftp.list";
pub const OP_SFTP_STAT: &str = "ssh.sftp.stat";
pub const OP_SFTP_READ: &str = "ssh.sftp.read";
pub const OP_SFTP_WRITE: &str = "ssh.sftp.write";
pub const OP_SFTP_MKDIR: &str = "ssh.sftp.mkdir";
pub const OP_SFTP_RENAME: &str = "ssh.sftp.rename";
pub const OP_SFTP_REMOVE: &str = "ssh.sftp.remove";

/// The most bytes one read or write moves (plan T5): 2 GiB.
pub const SFTP_MAX_BYTES: u64 = 2 << 30;
/// The most entries one `list` answers; more sets `truncated`.
pub const SFTP_MAX_ENTRIES: usize = 10_000;
/// The longest path, in bytes.
pub const SFTP_MAX_PATH: usize = 4096;

/// Where: the target and the jump hosts in front of it, as in `ssh.exec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshRoute {
    pub target: SshHop,
    /// At most `MAX_SSH_HOPS`.
    #[serde(default)]
    pub hops: Vec<SshHop>,
}

/// `ssh.sftp.list`: the entries of a directory, sorted by name, without `.` and `..`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpList {
    #[serde(flatten)]
    pub route: SshRoute,
    pub path: String,
}

/// `ssh.sftp.stat`: one path's attributes. A symlink is reported as a symlink unless `follow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpStat {
    #[serde(flatten)]
    pub route: SshRoute,
    pub path: String,
    #[serde(default)]
    pub follow: bool,
}

/// `ssh.sftp.read`: a file's bytes as `output` frames, from `offset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpRead {
    #[serde(flatten)]
    pub route: SshRoute,
    pub path: String,
    #[serde(default)]
    pub offset: u64,
}

/// `ssh.sftp.write`: a file from the Core's `output` frames, ended by `control` `eof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpWrite {
    #[serde(flatten)]
    pub route: SshRoute,
    pub path: String,
    /// Replace an existing file (`sftp_exists` when absent and the path is taken).
    #[serde(default)]
    pub overwrite: bool,
    /// The size the sender will send: over the cap is refused at once, and a different count at
    /// `eof` fails the transfer (nothing is left behind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Permission bits (`0o7777`) set on the file before any byte is written, so a file meant for
    /// its owner alone (Leyline's runner invite, `0o600`) is never readable by anyone else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

/// `ssh.sftp.mkdir`: one directory (its parent must exist).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpMkdir {
    #[serde(flatten)]
    pub route: SshRoute,
    pub path: String,
}

/// `ssh.sftp.rename`: `from` to `to`; `sftp_exists` when `to` is taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpRename {
    #[serde(flatten)]
    pub route: SshRoute,
    pub from: String,
    pub to: String,
}

/// `ssh.sftp.remove`: a file or symlink, or with `dir` an empty directory. Never recursive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpRemove {
    #[serde(flatten)]
    pub route: SshRoute,
    pub path: String,
    #[serde(default)]
    pub dir: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SftpKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// What the host said about one path. Every field is the host's word, so data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpEntry {
    /// The entry's name in a listing; the path as asked for `stat`.
    pub name: String,
    pub kind: SftpKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Permission bits (`0o7777`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Seconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

/// The answer to `ssh.sftp.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpEntries {
    pub entries: Vec<SftpEntry>,
    /// The directory has more than [`SFTP_MAX_ENTRIES`].
    #[serde(default)]
    pub truncated: bool,
}

/// The answer to `ssh.sftp.read` and `ssh.sftp.write`: the bytes moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpTransferred {
    pub bytes: u64,
}

/// The answer to `ssh.sftp.mkdir`, `rename` and `remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SftpDone {}

#[cfg(test)]
mod tests {
    use super::super::{Command, Frame};
    use super::*;

    /// The route's fields sit beside the op's own on the wire, and every op names itself.
    #[test]
    fn ops_carry_the_route_flat_and_round_trip() {
        let hop = serde_json::json!({"host": "h", "user": "u", "lease": "l_1"});
        let ops = [
            (OP_SFTP_LIST, serde_json::json!({"path": "/a"})),
            (
                OP_SFTP_STAT,
                serde_json::json!({"path": "/a", "follow": true}),
            ),
            (OP_SFTP_READ, serde_json::json!({"path": "/a", "offset": 9})),
            (
                OP_SFTP_WRITE,
                serde_json::json!({"path": "/a", "overwrite": true, "size": 3}),
            ),
            (OP_SFTP_MKDIR, serde_json::json!({"path": "/a"})),
            (
                OP_SFTP_RENAME,
                serde_json::json!({"from": "/a", "to": "/b"}),
            ),
            (
                OP_SFTP_REMOVE,
                serde_json::json!({"path": "/a", "dir": true}),
            ),
        ];
        for (op, mut body) in ops {
            body["op"] = op.into();
            body["target"] = hop.clone();
            let c: Command = serde_json::from_value(body.clone()).unwrap();
            assert_eq!(c.op(), op);
            // Defaults fill in (`port`, `hops`); the wire form parses back to the same command.
            let again: Command = serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
            assert_eq!(again, c);
            let frame = Frame::new(1, 0, super::super::Body::Command(c.clone()));
            assert_eq!(frame.body().unwrap(), Some(super::super::Body::Command(c)));
        }
    }
}
