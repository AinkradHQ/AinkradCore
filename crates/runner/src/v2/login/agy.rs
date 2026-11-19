//! Antigravity (agy) sign-in specifics (E7 review M1, M4). Its guided terminal is the riskiest of
//! the bound sign-ins (an agent fed by `login.input`), so it runs inside the session sandbox, takes
//! only menu choices and codes, and at most one agy account home exists per runner (its login also
//! lives in the runner user's OS keyring, which a home wipe cannot clear).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ainkrad_proto::v2::bound_key_ok;

/// What a wipe of an agy home answers in `LoginResult.error` next to `done`: the files are gone, the
/// OS keyring entry may not be (no tool here can clear it per account). The Core records it.
pub const KEYRING_NOT_CLEARED: &str = "keyring_not_cleared";

/// Held while the one-agy-home check and the home's creation happen, so two sign-ins cannot both pass.
pub(super) static START: Mutex<()> = Mutex::new(());

/// A line an agy sign-in takes: a menu choice (one or two digits) or a code (8 to 256 of
/// `[A-Za-z0-9_/-]`, no space; Google's start `4/`). Never free text. Mirrored by the Core.
pub(super) fn input_ok(text: &str) -> bool {
    ainkrad_proto::v2::agy_input_ok(text)
}

/// The sandbox environment of the sign-in: network open (it must reach Google), every limit the
/// runner's default, `state` hidden (the other accounts' homes), the scratch `tmp` private.
fn sandbox_env(scratch: &Path, state: &Path) -> Vec<(String, std::ffi::OsString)> {
    let own_tmp = std::env::temp_dir();
    let own_tmp = own_tmp.canonicalize().unwrap_or(own_tmp);
    vec![
        ("AINKRAD_SANDBOX".to_owned(), "1".into()),
        ("AINKRAD_SANDBOX_STATE".to_owned(), state.into()),
        ("AINKRAD_SANDBOX_TMP".to_owned(), scratch.join("tmp").into()),
        ("AINKRAD_SANDBOX_HIDE_TMP".to_owned(), own_tmp.into()),
        ("AINKRAD_SANDBOX_NETWORK".to_owned(), "allow".into()),
    ]
}

/// `program args` wrapped by the session sandbox: it may write only `home` (the account's own),
/// the scratch `home` and `tmp`. If the sandbox cannot be built the program is a path that does not
/// exist, so the sign-in fails to start (fail closed); it never runs unsandboxed.
pub(super) fn sandboxed(
    program: &Path,
    args: &[String],
    scratch: &Path,
    home: &Path,
    state: &Path,
) -> (PathBuf, Vec<String>) {
    let spec = ainkrad_harness::Spec {
        cwd: scratch.join("home"),
        config_dir: home.to_owned(),
        env: sandbox_env(scratch, state),
        ..Default::default()
    };
    let cmd = ainkrad_harness::sandbox_command(program.as_os_str(), args, &spec);
    let std = cmd.as_std();
    (
        PathBuf::from(std.get_program()),
        std.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
    )
}

/// Where the marker of an agy home lives: beside the homes, not in one (the sandbox writes its home).
fn marker(homes: &Path, key: &str) -> PathBuf {
    homes.join(format!(".agy-{key}"))
}

/// Records that the home `key` belongs to an agy sign-in.
pub(super) fn mark(homes: &Path, key: &str) -> std::io::Result<()> {
    std::fs::write(marker(homes, key), b"agy")
}

/// Whether the home `key` is an agy home.
pub(super) fn is_agy(homes: &Path, key: &str) -> bool {
    bound_key_ok(key) && std::fs::symlink_metadata(marker(homes, key)).is_ok_and(|m| m.is_file())
}

/// Forgets the marker of `key` (the home is gone).
pub(super) fn unmark(homes: &Path, key: &str) {
    let _ = std::fs::remove_file(marker(homes, key));
}

/// Whether an agy home already exists. A marker whose home is gone (a cancelled sign-in) is stale
/// and removed here.
pub(super) fn exists(homes: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(homes) else {
        return false;
    };
    let mut found = false;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(key) = name.strip_prefix(".agy-") else {
            continue;
        };
        match std::fs::symlink_metadata(homes.join(key)).is_ok_and(|m| m.is_dir()) {
            true => found = true,
            false => unmark(homes, key),
        }
    }
    found
}
