use super::*;

fn home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("citadel-mac-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A user agent that keeps the runner's own command line, escaped, logs under
/// `~/Library/Logs`, and never holds the key. Written and removed under a temp home only;
/// nothing is loaded.
#[test]
fn installs_and_removes_a_keep_alive_agent() {
    let home = home("agent");
    let args: Vec<String> = [
        "wss://citadel.lan/runner/v1/connect",
        "--key-file",
        "/Users/a/.ainkrad-runner/key",
        "--git-name",
        "Citadel <Bot> & Co",
    ]
    .map(str::to_owned)
    .into();
    let program = Path::new("/opt/homebrew/bin/ainkrad-runner");
    let (path, load) = install(&home, program, &args).unwrap();
    assert_eq!(
        path,
        home.join("Library/LaunchAgents/com.ainkrad.ainkrad-runner.plist")
    );
    assert!(home.join("Library/Logs/ainkrad-runner").is_dir());
    let plist = std::fs::read_to_string(&path).unwrap();
    for part in [
        "<string>/opt/homebrew/bin/ainkrad-runner</string>",
        "<string>--key-file</string>",
        "<string>Citadel &lt;Bot&gt; &amp; Co</string>",
        "<key>KeepAlive</key>\n\t<true/>",
        "<key>RunAtLoad</key>\n\t<true/>",
        "Library/Logs/ainkrad-runner/runner.log</string>",
        "<key>PATH</key>",
    ] {
        assert!(plist.contains(part), "{part} missing:\n{plist}");
    }
    assert!(!plist.contains("CITADEL_RUNNER_KEY"));
    if cfg!(target_os = "macos") {
        let lint = Command::new("plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .unwrap();
        assert!(lint.status.success(), "{lint:?}");
    }
    let uid = std::fs::metadata(&home).unwrap().uid();
    let bootstrap = &load[1];
    assert_eq!(
        bootstrap[..3],
        ["launchctl", "bootstrap", &format!("gui/{uid}")]
    );
    assert_eq!(bootstrap[3], path.display().to_string());

    let (existed, stop) = uninstall(&home).unwrap();
    assert!(existed && !path.exists());
    assert_eq!(
        stop[0],
        ["launchctl", "bootout", &format!("gui/{uid}/{LABEL}")]
    );
    assert!(!uninstall(&home).unwrap().0);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_mac_offers_macos_and_xcode_when_it_has_it() {
    let tags = default_tags();
    if !cfg!(target_os = "macos") {
        assert!(tags.is_empty());
        return;
    }
    assert_eq!(tags[0], "macos");
    let xcode = Command::new("xcode-select").arg("-p").output();
    let has = xcode.is_ok_and(|o| o.status.success());
    assert_eq!(tags.contains(&"xcode".to_owned()), has, "{tags:?}");
}

/// No environment variable may claim the host is a sandbox (review A M1): launchd must not
/// carry one into the runner.
#[test]
fn the_launchd_agent_passes_no_sandbox_claim() {
    assert!(PASSED_ENV.iter().all(|n| !n.contains("SANDBOX")));
}
