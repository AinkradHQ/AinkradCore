//! What the runner says of itself (1.20): its `RunnerInfo`, and the tail of its own log.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use ainkrad_proto::runner::RunnerInfo;

use super::*;

/// The most of the log's end read for a tail.
const TAIL_BYTES: u64 = 256 * 1024;

impl<E: Executor> Daemon<E> {
    /// Its state now: one run at a time, so one slot.
    pub(crate) fn info(&self) -> RunnerInfo {
        RunnerInfo {
            slots: 1,
            uptime_secs: self.started.elapsed().as_secs(),
            logins: self.executor.logins(),
            slept_secs: self.slept,
            power_nap: self.power_nap,
        }
    }

    pub(crate) fn status(&self) -> RunnerMessage {
        RunnerMessage::Status {
            info: Box::new(self.info()),
        }
    }
}

/// The last `lines` lines of `log`, each redacted, or why not.
pub(crate) fn tail(
    log: Option<&Path>,
    lines: u32,
    redactor: &Redactor,
) -> Result<Vec<String>, String> {
    let Some(log) = log else {
        return Err("this runner keeps no log file".to_owned());
    };
    let mut file = std::fs::File::open(log).map_err(|e| format!("{}: {e}", log.display()))?;
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    let from = len.saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(from))
        .map_err(|e| e.to_string())?;
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes);
    let mut all: Vec<&str> = text.lines().collect();
    // A read from the middle of the file starts mid-line.
    if from > 0 && !all.is_empty() {
        all.remove(0);
    }
    let keep = all.len().saturating_sub(lines as usize);
    Ok(all[keep..].iter().map(|l| redactor.text(l)).collect())
}

/// Files that hold a harness's login in its config dir: Codex's, OpenCode's (under its
/// `XDG_DATA_HOME`), Claude's off macOS.
const LOGIN_FILES: &[&str] = &["auth.json", "data/opencode/auth.json", ".credentials.json"];

/// Whether `dir` holds a login. Claude on macOS and agy keep theirs in the keychain or their
/// own home, which no file here shows: `unknown` rather than a wrong `logged_out`.
fn login_state(dir: &Path, harness: Option<&str>) -> &'static str {
    match (LOGIN_FILES.iter().any(|f| dir.join(f).exists()), harness) {
        (true, _) => "logged_in",
        (false, Some("codex" | "opencode")) => "logged_out",
        (false, _) => "unknown",
    }
}

/// Each harness's own config dir under `root`, each account's (`accounts/*`), and each token
/// file under `credentials` (present: logged in), with its state.
pub(crate) fn logins<'a>(
    root: &Path,
    credentials: &Path,
    harnesses: impl Iterator<Item = &'a str>,
) -> Vec<ainkrad_proto::runner::Login> {
    use ainkrad_proto::runner::Login;
    let mut out = vec![];
    for name in harnesses {
        let dir = root.join(name);
        if dir.is_dir() {
            let state = login_state(&dir, Some(name)).to_owned();
            let (dir, harness) = (name.to_owned(), Some(name.to_owned()));
            out.push(Login {
                dir,
                harness,
                state,
            });
        }
    }
    let names = |dir: &Path, dirs: bool| -> Vec<String> {
        let mut found: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().is_dir() == dirs)
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        found.sort();
        found
    };
    for name in names(&root.join("accounts"), true) {
        let state = login_state(&root.join("accounts").join(&name), None).to_owned();
        out.push(Login {
            dir: format!("accounts/{name}"),
            harness: None,
            state,
        });
    }
    for name in names(credentials, false) {
        out.push(Login {
            dir: format!("credentials/{name}"),
            harness: None,
            state: "logged_in".to_owned(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tail_is_the_last_lines_redacted() {
        let dir = std::env::temp_dir().join(format!("citadel-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("runner.log");
        std::fs::write(&log, "one\ntwo key=cit_runner_secret\nthree\n").unwrap();
        let mut r = Redactor::new();
        r.known("runner_key", "cit_runner_secret");
        let got = tail(Some(&log), 2, &r).unwrap();
        assert_eq!(got.len(), 2);
        assert!(got[0].starts_with("two") && !got[0].contains("cit_runner_secret"));
        assert_eq!(got[1], "three");
        assert!(tail(None, 2, &r).is_err());
    }

    #[test]
    fn logins_are_found_by_their_files() {
        let root = std::env::temp_dir().join(format!("citadel-logins-{}", std::process::id()));
        for d in ["codex", "opencode", "claude", "accounts/a", "credentials"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("codex/auth.json"), "{}").unwrap();
        std::fs::write(root.join("credentials/a.token"), "x").unwrap();
        let got = logins(
            &root,
            &root.join("credentials"),
            ["codex", "opencode", "claude"].into_iter(),
        );
        let states: Vec<(&str, &str)> = got
            .iter()
            .map(|l| (l.dir.as_str(), l.state.as_str()))
            .collect();
        assert_eq!(
            states,
            [
                ("codex", "logged_in"),
                ("opencode", "logged_out"),
                ("claude", "unknown"),
                ("accounts/a", "unknown"),
                ("credentials/a.token", "logged_in"),
            ]
        );
    }
}
