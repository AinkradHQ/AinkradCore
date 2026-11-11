//! What the runner tells the Core about its host in `hello` (`RunnerFacts`): display only.

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::OnceLock;

use ainkrad_proto::v2::RunnerFacts;

/// The first line a command prints, if it ran well.
fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let line = text.lines().next()?.trim();
    (out.status.success() && !line.is_empty()).then(|| line.to_owned())
}

/// `NAME VERSION_ID` of an os-release file, e.g. `Ubuntu 26.04`.
pub(super) fn pretty_from_os_release(text: &str) -> Option<String> {
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_owned())
            .filter(|v| !v.is_empty())
    };
    match (get("NAME"), get("VERSION_ID")) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        _ => get("PRETTY_NAME"),
    }
}

/// The host's own facts, read once per process; `tools` are the harnesses this runner probed.
pub fn gather(
    tools: &BTreeMap<String, String>,
    policy: Option<ainkrad_proto::v2::RunnerPolicy>,
    own_logins: Vec<String>,
) -> RunnerFacts {
    static HOST: OnceLock<(Option<String>, Option<String>, Option<bool>)> = OnceLock::new();
    let (os_pretty, user, root) = HOST.get_or_init(|| {
        let os = if cfg!(target_os = "macos") {
            run("sw_vers", &["-productVersion"]).map(|v| format!("macOS {v}"))
        } else {
            std::fs::read_to_string("/etc/os-release")
                .ok()
                .and_then(|t| pretty_from_os_release(&t))
        };
        let uid = run("id", &["-u"]);
        (os, run("id", &["-un"]), uid.map(|u| u == "0"))
    });
    RunnerFacts {
        os_pretty: os_pretty.clone(),
        user: user.clone(),
        root: *root,
        // What the host has installed (probed now), with the harnesses the agent driver proved.
        tools: {
            let mut all = super::tools::probe_tools();
            all.extend(tools.clone());
            all
        },
        own_logins,
        policy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_reads_as_name_and_version() {
        let t = "PRETTY_NAME=\"Ubuntu 26.04 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\n";
        assert_eq!(pretty_from_os_release(t).as_deref(), Some("Ubuntu 26.04"));
        assert_eq!(
            pretty_from_os_release("PRETTY_NAME=Arch").as_deref(),
            Some("Arch")
        );
        assert_eq!(pretty_from_os_release(""), None);
    }

    #[test]
    fn a_harness_with_a_login_file_is_an_own_login_and_reaches_the_facts() {
        let root = std::env::temp_dir().join(format!("own-logins-{}", std::process::id()));
        std::fs::create_dir_all(root.join("claude")).unwrap();
        std::fs::create_dir_all(root.join("codex")).unwrap();
        std::fs::write(root.join("claude/.credentials.json"), "{}").unwrap();
        let found = crate::state::logins(
            &root,
            &root.join("credentials"),
            ["claude", "codex"].into_iter(),
        );
        let own = super::super::agent::own_logins(found);
        assert_eq!(own, ["claude"]);
        let facts = gather(&BTreeMap::new(), None, own);
        assert_eq!(facts.own_logins, ["claude"]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
