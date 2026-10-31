//! Mac runners (E3.11): default tags, and a launchd user agent that keeps the runner up.
//!
//! The agent is `~/Library/LaunchAgents/<LABEL>.plist`, in the user's GUI domain (harness
//! logins and the keychain live there), `RunAtLoad` and `KeepAlive`, logging to
//! `~/Library/Logs/ainkrad-runner/runner.log`. Its arguments are the runner's own command
//! line, so the key comes from `--key-file`: it is never written into the plist. It copies
//! the few variables the runner reads (`PATH`, `CITADEL_GIT_ASKPASS`), since launchd starts
//! agents with almost none.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const LABEL: &str = "com.ainkrad.ainkrad-runner";

/// The variables the agent gets from the installing shell, when set.
const PASSED_ENV: &[&str] = &["PATH", "CITADEL_GIT_ASKPASS"];

/// The tags a runner offers when none are given: `macos` on a Mac, plus `xcode` when
/// `xcode-select -p` finds a developer directory. Elsewhere none.
pub fn default_tags() -> Vec<String> {
    if !cfg!(target_os = "macos") {
        return vec![];
    }
    let mut tags = vec!["macos".to_owned()];
    let xcode = Command::new("xcode-select")
        .arg("-p")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if xcode.is_ok_and(|s| s.success()) {
        tags.push("xcode".to_owned());
    }
    tags
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The agent's plist: `program args…`, its environment `env`, logs under `logs`.
pub fn plist(program: &Path, args: &[String], env: &[(String, String)], logs: &Path) -> String {
    let string = |s: &str| format!("\t\t<string>{}</string>\n", escape(s));
    let argv: String = std::iter::once(program.display().to_string())
        .chain(args.iter().cloned())
        .map(|a| string(&a))
        .collect();
    let vars: String = env
        .iter()
        .map(|(k, v)| format!("\t\t<key>{}</key>\n{}", escape(k), string(v)))
        .collect();
    let log = escape(&logs.join("runner.log").display().to_string());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \t<key>Label</key>\n\t<string>{LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n{argv}\t</array>\n\
         \t<key>EnvironmentVariables</key>\n\t<dict>\n{vars}\t</dict>\n\
         \t<key>RunAtLoad</key>\n\t<true/>\n\
         \t<key>KeepAlive</key>\n\t<true/>\n\
         \t<key>ProcessType</key>\n\t<string>Background</string>\n\
         \t<key>StandardOutPath</key>\n\t<string>{log}</string>\n\
         \t<key>StandardErrorPath</key>\n\t<string>{log}</string>\n\
         </dict>\n</plist>\n"
    )
}

/// The agent's plist path under `home`.
pub fn plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

/// The user's GUI domain, `gui/<uid>`, from the owner of `home`.
fn domain(home: &Path) -> std::io::Result<String> {
    Ok(format!("gui/{}", std::fs::metadata(home)?.uid()))
}

/// Writes the agent for `program args…` under `home`: its plist path and the `launchctl`
/// commands that load it.
pub fn install(
    home: &Path,
    program: &Path,
    args: &[String],
) -> std::io::Result<(PathBuf, Vec<Vec<String>>)> {
    let logs = home.join("Library/Logs/ainkrad-runner");
    std::fs::create_dir_all(&logs)?;
    let path = plist_path(home);
    std::fs::create_dir_all(path.parent().expect("a parent"))?;
    let env: Vec<(String, String)> = PASSED_ENV
        .iter()
        .filter_map(|name| Some(((*name).to_owned(), std::env::var(name).ok()?)))
        .collect();
    std::fs::write(&path, plist(program, args, &env, &logs))?;
    let domain = domain(home)?;
    let shown = path.display().to_string();
    let load = vec![
        vec![
            "launchctl".into(),
            "bootout".into(),
            format!("{domain}/{LABEL}"),
        ],
        vec!["launchctl".into(), "bootstrap".into(), domain, shown],
    ];
    Ok((path, load))
}

/// Removes the agent's plist under `home`, if there is one: whether it was there, and the
/// `launchctl` command that stops the agent.
pub fn uninstall(home: &Path) -> std::io::Result<(bool, Vec<Vec<String>>)> {
    let path = plist_path(home);
    let existed = path.exists();
    if existed {
        std::fs::remove_file(&path)?;
    }
    let stop = vec![
        "launchctl".into(),
        "bootout".into(),
        format!("{}/{LABEL}", domain(home)?),
    ];
    Ok((existed, vec![stop]))
}

#[cfg(test)]
mod tests;
