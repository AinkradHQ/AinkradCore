//! Environment handoff for launchers and private roots: `--setenv` pairs, descriptor 3, and the
//! launcher's own clean environment.

use super::*;

/// `env K=V…` for a command a host-view launcher starts, with the launcher itself left clean: on
/// Linux each variable becomes a `--setenv` before `--chdir`, on macOS the program is run through
/// `/usr/bin/env` after `--`. Returns the argv unchanged when there is nothing to set.
pub fn inject_env(args: &mut Vec<String>, env: &BTreeMap<String, String>) {
    // macOS: the variables stay in `sandbox-exec`'s own environment (see `wrap_private`).
    if cfg!(target_os = "macos") || env.is_empty() {
        return;
    }
    if let Some(at) = args.iter().position(|a| a == "--chdir") {
        let ins: Vec<String> = env
            .iter()
            .flat_map(|(k, v)| ["--setenv".to_owned(), k.clone(), v.clone()])
            .collect();
        args.splice(at..at, ins);
    }
}

/// Moves every `--setenv K V` of bubblewrap's argv into the bytes of a pipe, so no variable (a
/// terminal's secret) is in the process listing: `/proc/<pid>/cmdline` is world-readable, a pipe is
/// not. The first one is replaced by `--args 3` (bubblewrap reads its options from descriptor 3
/// there, in order, so `--clearenv` still comes first). The bytes are NUL-terminated arguments;
/// `None` when there is nothing to move or the launcher is not bubblewrap (macOS: `sandbox-exec`
/// has no such option, its variables travel in its environment). The caller hands them to the host
/// as `Spec::fd3`.
pub fn setenv_to_fd(args: &mut Vec<String>) -> Option<Vec<u8>> {
    if cfg!(target_os = "macos") {
        return None;
    }
    // Only bubblewrap's own options: what follows the first `--` is the program and its
    // arguments, where a `--setenv K V` is just text.
    let end = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let first = args[..end].iter().position(|a| a == "--setenv")?;
    let mut bytes = Vec::new();
    let mut kept = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        if i < end && args[i] == "--setenv" && i + 2 < end {
            for a in &args[i..i + 3] {
                bytes.extend_from_slice(a.as_bytes());
                bytes.push(0);
            }
            if i == first {
                kept.push("--args".to_owned());
                kept.push("3".to_owned());
            }
            i += 3;
        } else {
            kept.push(args[i].clone());
            i += 1;
        }
    }
    *args = kept;
    Some(bytes)
}

/// The environment a host-view launcher gets itself.
pub fn launcher_env() -> BTreeMap<String, String> {
    BTreeMap::from([("PATH".to_owned(), LAUNCHER_PATH.to_owned())])
}
