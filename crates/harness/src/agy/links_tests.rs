//! The runner links the spec's files into agy's home, which the agent can write to: a planted
//! link where a directory belongs must not carry those writes and removals outside it.

use super::*;

#[test]
fn a_planted_directory_link_does_not_carry_the_runners_links_outside_the_home() {
    let dir = std::env::temp_dir().join(format!("citadel-agy-planted-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let outside = dir.join("outside");
    std::fs::create_dir_all(outside.join("config")).unwrap();
    // Files the runner would otherwise remove or replace through the link.
    std::fs::write(outside.join("GEMINI.md"), "keep").unwrap();
    std::fs::write(outside.join("config/mcp_config.json"), "keep").unwrap();
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    // `.gemini` is a link to a directory outside; so is `.gemini/config`'s stand-in below it.
    std::os::unix::fs::symlink(&outside, home.join(".gemini")).unwrap();
    let (mcp, notes) = (dir.join("mcp.json"), dir.join("instructions.md"));
    std::fs::write(&mcp, "{}").unwrap();
    std::fs::write(&notes, "# Skill").unwrap();
    let spec = Spec {
        config_dir: home.clone(),
        mcp_config: Some(mcp.clone()),
        instructions: Some(notes),
        ..Spec::default()
    };
    link_files(&spec).unwrap();
    assert_eq!(
        std::fs::read_to_string(outside.join("GEMINI.md")).unwrap(),
        "keep"
    );
    assert_eq!(
        std::fs::read_to_string(outside.join("config/mcp_config.json")).unwrap(),
        "keep"
    );
    let gemini = std::fs::symlink_metadata(home.join(".gemini")).unwrap();
    assert!(gemini.is_dir() && !gemini.is_symlink());
    assert_eq!(
        std::fs::read_link(home.join(".gemini/config/mcp_config.json")).unwrap(),
        mcp
    );
    // The settings directory the spawn writes into is made the same way.
    std::fs::remove_dir_all(home.join(".gemini")).unwrap();
    std::fs::create_dir_all(home.join(".gemini")).unwrap();
    std::os::unix::fs::symlink(&outside, home.join(".gemini/antigravity-cli")).unwrap();
    crate::safe_fs::real_dir(&home, Path::new(".gemini/antigravity-cli")).unwrap();
    crate::safe_fs::write_replacing(
        &home.join(".gemini/antigravity-cli"),
        "settings.json",
        GATEWAY_SETTINGS,
    )
    .unwrap();
    assert!(!outside.join("settings.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

fn hooks_spec(home: &Path, env: &[(&str, &str)]) -> Spec {
    Spec {
        config_dir: home.to_path_buf(),
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).into()))
            .collect(),
        ..Spec::default()
    }
}

#[test]
fn a_tools_session_gets_a_stop_hook_in_its_private_home_only() {
    let dir = std::env::temp_dir().join(format!("citadel-agy-hooks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("home");
    let at = home.join(".gemini/config/hooks.json");
    let spec = hooks_spec(
        &home,
        &[
            (crate::connections::SLOT_SOCK, "/run/a/tools.sock"),
            (crate::connections::SLOT_FWD, "/opt/ainkrad-runner"),
        ],
    );
    link_files(&spec).unwrap();
    write_hooks(&spec).unwrap();
    let got: Value = serde_json::from_slice(&std::fs::read(&at).unwrap()).unwrap();
    let hook = &got["ainkrad-brain"]["Stop"][0];
    assert_eq!(hook["type"], "command");
    assert_eq!(
        hook["command"],
        "'/opt/ainkrad-runner' ainkrad-hook checkpoint '/run/a/tools.sock'"
    );
    assert_eq!(hook["timeout"], 2);
    // Only `Stop`, and no credential anywhere in the file.
    assert_eq!(got["ainkrad-brain"].as_object().unwrap().len(), 1);
    assert!(!std::fs::read_to_string(&at).unwrap().contains("Bearer"));
    // A planted link at the file is replaced, never followed.
    let outside = dir.join("outside");
    std::fs::write(&outside, "keep").unwrap();
    std::fs::remove_file(&at).unwrap();
    std::os::unix::fs::symlink(&outside, &at).unwrap();
    write_hooks(&spec).unwrap();
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
    assert!(!std::fs::symlink_metadata(&at).unwrap().is_symlink());
    // A session without the slot loses a stale file; no file is no error.
    let plain = hooks_spec(&home, &[]);
    write_hooks(&plain).unwrap();
    assert!(!at.exists());
    write_hooks(&plain).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
