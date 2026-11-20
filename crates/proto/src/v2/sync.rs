//! Workspace sync (E15-2, spec §4.5): the delta protocol between the Core's canonical workspace and
//! a runner's warm per-project cache, driver `sync` (a runner that takes these ops lists them under
//! a driver named [`CAP_SYNC`]). Hashing is blake3, files cut into fixed [`CHUNK_BYTES`] chunks
//! (ponytail: content-defined chunking only if big binaries churn).
//!
//! **Chunk frames.** The bytes of a `sync.push` (Core to runner) and a `sync.pull` (runner to Core)
//! travel as plain `output` frames: the files' bytes in the order the chunks are listed
//! (`SyncPush::put` entries' `chunks`, then `SyncPull::paths` files' chunks), every chunk sent even
//! when repeated, cut into frames of at most [`SYNC_FRAME_BYTES`] (a 1 MiB hashing chunk is four
//! frames; a frame never spans two chunks). The receiver hashes each whole chunk and refuses a
//! mismatch (`hash_mismatch`). These frames are what the spec calls `SyncChunk`s. Credit: on a
//! `sync.*` stream each side starts with [`SYNC_STREAM_WINDOW`] instead of `STREAM_WINDOW`, and
//! grants more as it writes, for push, pull and watch alike.
//!
//! **Watch.** The first `SyncEvent` of a `sync.watch` (`seq` 1) is a full snapshot of the folder
//! (every entry in `put`); later ones are deltas. Within one event `delete` applies before `put`.
//! A `put` without `inline` bytes is fetched with `sync.pull`.
//!
//! **Rules.** Every op that walks or hashes a tree carries the project's [`SyncRules`] itself, so
//! the runner applies exactly the Core's include/exclude and both ends' tree hashes agree.
//!
//! **Paths** are wire paths ([`super::wire_path_problem`]); either end refuses another with
//! `path_refused`. `.git` is never synced.

use serde::{Deserialize, Serialize};

pub const OP_SYNC_MANIFEST: &str = "sync.manifest";
pub const OP_SYNC_PUSH: &str = "sync.push";
pub const OP_SYNC_PULL: &str = "sync.pull";
pub const OP_SYNC_WATCH: &str = "sync.watch";
pub const OP_SYNC_DROP: &str = "sync.drop";

/// The driver (and capability) name of a runner that speaks this protocol.
pub const CAP_SYNC: &str = "sync";

/// The fixed chunk size: 1 MiB.
pub const CHUNK_BYTES: u64 = 1024 * 1024;
/// A file over this is skipped with a warning (256 MB).
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// A job whose sync in exceeds this runs on the Core instead (4096 MB).
pub const MAX_SYNC_IN_BYTES: u64 = 4096 * 1024 * 1024;
/// Sync out beyond this fails the job with `outputs_too_large` (2048 MB).
pub const MAX_SYNC_OUT_BYTES: u64 = 2048 * 1024 * 1024;
/// A watched file up to this size travels inline in its `SyncEvent`.
pub const MAX_INLINE_BYTES: usize = 256 * 1024;
/// A watch sends an event at least this often while anything changed.
pub const WATCH_INTERVAL_MS: u64 = 500;
/// The most file bytes one `output` frame of a `sync.*` stream carries (256 KiB).
pub const SYNC_FRAME_BYTES: usize = 256 * 1024;
/// The credit each side of a `sync.*` stream starts with (4 MiB: four 1 MiB chunks in flight).
pub const SYNC_STREAM_WINDOW: u64 = 4 * 1024 * 1024;

/// A blake3 hash, lowercase hex on the wire (64 characters).
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, schemars::JsonSchema)]
pub struct Hash(#[schemars(with = "String")] pub [u8; 32]);

/// The hash of a whole tree: blake3 over its sorted entries (E15-2 defines the exact fold).
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, schemars::JsonSchema)]
pub struct TreeHash(#[schemars(with = "String")] pub [u8; 32]);

fn to_hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

macro_rules! hex_newtype {
    ($t:ident) => {
        impl Serialize for $t {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&to_hex(&self.0))
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                from_hex(&s)
                    .map(Self)
                    .ok_or_else(|| serde::de::Error::custom("not 64 lowercase hex characters"))
            }
        }
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&to_hex(&self.0))
            }
        }
        impl $t {
            pub fn hex(&self) -> String {
                to_hex(&self.0)
            }
        }
    };
}
hex_newtype!(Hash);
hex_newtype!(TreeHash);

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    #[default]
    File,
    /// A relative symlink that resolves inside the project; `Entry::link` is its target.
    Symlink,
    /// A kind from a newer peer: skipped. Never sent.
    #[serde(other)]
    Unknown,
}

/// One file of a tree. Directories are implied by their files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct Entry {
    /// A wire path.
    pub path: String,
    pub kind: EntryKind,
    pub exec: bool,
    pub size: u64,
    /// The whole file's hash.
    pub hash: Hash,
    /// Each [`CHUNK_BYTES`] chunk's hash, in order; empty for an empty file or a symlink.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<Hash>,
    /// A symlink's relative target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

/// Core to runner: the manifest of the runner's cache of `project`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncManifest {
    pub project: i64,
    /// `l_…`: the per (device, project, job or session) lease; without it, `not_found`.
    pub lease: String,
    /// The hash of `rules` (a runner may keep its index per rules hash).
    pub rules_hash: Hash,
    /// The rules the manifest is taken under.
    pub rules: SyncRules,
    /// F0-bis (E15-4): seed an empty cache with `git clone` from the Core's copy of the project's
    /// repo before the manifest is taken (spec §4.4). The Core serves the copy only while it holds a
    /// lease for this runner. Absent: the cache is not seeded (or already is).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<super::run::RunClone>,
}

/// The project's include/exclude rules (§4.4, the built-ins merged with `.ainkrad/jobs.toml
/// [sync]` by the Core). Globs are gitignore-style, relative to the project root. `.git/` is
/// excluded whatever these say.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncRules {
    /// Synced although an exclude matches (secret-shaped files the project lists, for one).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// Never synced in (build output, secret-shaped files).
    pub exclude: Vec<String>,
    /// Synced out after a job even inside an excluded dir (`target/release/app`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<String>,
}

/// Runner to Core: the answer to `sync.manifest`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncManifestReply {
    pub entries: Vec<Entry>,
    pub tree: TreeHash,
}

/// Core to runner: apply a delta to the cache, then the chunk frames of `put`. Refused with
/// `base_mismatch` when the cache is not at `base`, `hash_mismatch` for a chunk or file that does
/// not hash as listed, `path_refused` for a path that is not a wire path.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncPush {
    pub project: i64,
    pub lease: String,
    pub base: TreeHash,
    pub put: Vec<Entry>,
    /// Wire paths to delete.
    pub delete: Vec<String>,
    /// The tree the cache must hold afterwards; another is `hash_mismatch`.
    pub want_tree: TreeHash,
    /// The rules `want_tree` is hashed under.
    pub rules: SyncRules,
    /// A per-file base, for a person's write into an overflow session (§4.6): each `(path, the
    /// hash the Core last saw)`. When present the push conflicts only where one of these files
    /// changed (`base_mismatch`), and `base` is not checked. Empty: the whole-tree `base`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub base_files: Vec<(String, Hash)>,
    /// The overflow session (`as_…`) whose live folder the push writes, as `sync.watch` names it.
    /// Absent: the project's cache, or the session the lease's watch registered (older Cores).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// Runner to Core: the answer to `sync.push`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncPushed {
    pub tree: TreeHash,
}

/// Core to runner: send these files' chunks (credited `output` frames), from a cache or a session
/// folder.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncPull {
    pub project: i64,
    /// The project's cache (empty) or an overflow session's id (`as_…`).
    pub cache_or_session: String,
    /// `(wire path, the hash the Core expects)`; a file that no longer hashes so is `hash_mismatch`.
    pub paths: Vec<(String, Hash)>,
    /// As in [`SyncPush`].
    pub lease: String,
}

/// Runner to Core: the answer to `sync.pull`, after the last chunk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncPulled {
    pub count: u64,
}

/// Core to runner: stream every change in an overflow session's folder until `close`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncWatch {
    pub session: String,
    pub lease: String,
    /// The rules the watched tree is taken under.
    pub rules: SyncRules,
}

/// A small file's bytes, carried in its event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct InlineFile {
    pub path: String,
    /// Standard base64, at most [`MAX_INLINE_BYTES`] decoded.
    pub data: String,
}

/// Runner to Core on a `sync.watch` stream (a `control` body `sync_event`), at most every
/// [`WATCH_INTERVAL_MS`] while something changed. A `put` entry with no `inline` is pulled.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncEvent {
    /// From 1, by one, per watch.
    pub seq: u64,
    pub put: Vec<Entry>,
    pub delete: Vec<String>,
    pub inline: Vec<InlineFile>,
}

/// Runner to Core: the last frame of `sync.watch` (after `close`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncWatched {
    pub last_seq: u64,
}

/// Core to runner: forget the cache of `project` (it was archived, or the session ended).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncDrop {
    pub project: i64,
}

/// Runner to Core: the answer to `sync.drop`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SyncDropped {
    pub bytes_freed: u64,
}

// No `Debug` with a lease (secrets review L4).
macro_rules! lease_debug {
    ($t:ident, $($f:ident),*) => {
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($t))$(.field(stringify!($f), &self.$f))*.finish_non_exhaustive()
            }
        }
    };
}
lease_debug!(SyncManifest, project);
lease_debug!(SyncPush, project, base, want_tree);
lease_debug!(SyncPull, project, cache_or_session);
lease_debug!(SyncWatch, session);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_lowercase_hex_and_refuse_anything_else() {
        let h = Hash([0xab; 32]);
        let s = serde_json::to_string(&h).unwrap();
        assert_eq!(s, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<Hash>(&s).unwrap(), h);
        assert!(serde_json::from_str::<Hash>(&format!("\"{}\"", "AB".repeat(32))).is_err());
        assert!(serde_json::from_str::<TreeHash>("\"ab\"").is_err());
    }
}
