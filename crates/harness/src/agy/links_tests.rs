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
