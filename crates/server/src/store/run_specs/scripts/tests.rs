use super::*;

fn app(c: &Converted) -> &Service {
    &c.spec.services["app"]
}

/// Every draft must pass the P4-01 validator when it goes through JSON like a saved spec.
fn round_trips(c: &Converted) {
    let json = serde_json::to_value(&c.spec).unwrap();
    assert_eq!(spec::parse(&json).unwrap(), c.spec);
}

#[test]
fn package_json_drafts_its_start_script() {
    let t = r#"{"name":"tideway","engines":{"node":">=20.11"},
        "scripts":{"build":"tsc","start":"node server.js --port 4100"}}"#;
    let c = package_json(t, "web", "", None).unwrap();
    round_trips(&c);
    let s = app(&c);
    assert_eq!(s.image.as_deref(), Some("node:20"));
    assert_eq!(s.repo.as_deref(), Some("web"));
    assert_eq!(s.workdir.as_deref(), Some("/repo/web"));
    assert_eq!(
        s.command.as_ref().unwrap(),
        &["sh", "-c", "npm install && npm run start"]
    );
    assert_eq!(
        s.ports,
        vec![Port {
            port: 4100,
            expose: true
        }]
    );
}

#[test]
fn package_json_in_a_folder_uses_dev_and_the_named_package_manager() {
    let t = r#"{"packageManager":"pnpm@9.1.0","scripts":{"dev":"vite"}}"#;
    let c = package_json(t, "web", "apps/site/", Some("node:18")).unwrap();
    round_trips(&c);
    let s = app(&c);
    assert_eq!(s.image.as_deref(), Some("node:18"));
    assert_eq!(s.workdir.as_deref(), Some("/repo/web/apps/site"));
    assert!(s.command.as_ref().unwrap()[2].starts_with("corepack enable && pnpm install"));
    assert!(s.ports.is_empty());
    assert!(c.not_converted.iter().any(|n| n.path == "ports"));
}

#[test]
fn package_json_without_a_start_is_could_not_draft() {
    for t in [
        r#"{"name":"lib","scripts":{"build":"tsc"}}"#,
        r#"{"name":"lib"}"#,
        r#"{"scripts":{"start":5}}"#,
        "not json",
        "[]",
    ] {
        assert!(package_json(t, "web", "", None).is_err(), "{t}");
    }
}

#[test]
fn a_makefile_needs_an_image_and_a_run_like_target() {
    let t =
        "build:\n\tgo build ./...\n\nrun: build\n\tPORT=8081 ./bin/app\n\nclean:\n\trm -r bin\n";
    assert!(makefile(t, "api", "", None).unwrap_err().contains("image"));
    let c = makefile(t, "api", "", Some("golang:1.23")).unwrap();
    round_trips(&c);
    let s = app(&c);
    assert_eq!(s.command.as_ref().unwrap(), &["make", "run"]);
    assert_eq!(s.ports[0].port, 8081);
    // `runtime:` is not `run:`, a variable assignment is not a target.
    let t = "runtime:\n\ttrue\nstart := 1\n";
    assert!(makefile(t, "api", "", Some("golang:1.23")).is_err());
}

#[test]
fn run_sh_uses_its_shebang_shell_and_refuses_other_interpreters() {
    let c = run_sh(
        "#!/usr/bin/env bash\nexec ./serve --port=9000\n",
        "web",
        "bin",
        "run.sh",
        None,
    )
    .unwrap();
    round_trips(&c);
    let s = app(&c);
    assert_eq!(s.command.as_ref().unwrap(), &["bash", "run.sh"]);
    assert_eq!(s.workdir.as_deref(), Some("/repo/web/bin"));
    assert_eq!(s.ports[0].port, 9000);
    let c = run_sh("echo hi\n", "web", "", "run.sh", None).unwrap();
    assert_eq!(app(&c).command.as_ref().unwrap(), &["sh", "run.sh"]);
    let e = run_sh("#!/usr/bin/python3\nprint(1)\n", "web", "", "run.sh", None).unwrap_err();
    assert!(e.contains("only sh and bash"), "{e}");
}

#[test]
fn a_bad_image_is_refused_by_the_validator_and_nothing_is_run() {
    let e = run_sh("echo hi", "web", "", "run.sh", Some("--privileged")).unwrap_err();
    assert!(e.contains("image"), "{e}");
}

#[test]
fn draft_picks_the_converter_by_name_and_caps_the_size() {
    let (origin, _) = draft(
        "package.json",
        r#"{"scripts":{"start":"x"}}"#,
        "web",
        "",
        None,
    )
    .unwrap();
    assert_eq!(origin, "package_json");
    let (origin, c) = draft(
        "compose.yaml",
        "services:\n  web:\n    image: nginx:1\n",
        "web",
        "",
        None,
    )
    .unwrap();
    assert_eq!((origin, c.spec.services.len()), ("compose", 1));
    assert!(draft("notes.txt", "x", "web", "", None).is_err());
    assert!(draft("run.sh", &"#".repeat(MAX_BYTES + 1), "web", "", None).is_err());
}

#[test]
fn port_in_skips_words_that_merely_contain_port() {
    assert_eq!(port_in("export PORT=3000"), Some(3000));
    assert_eq!(port_in(r#""port": 4000"#), Some(4000));
    assert_eq!(port_in("import os; port 0"), None);
    assert_eq!(port_in("PORT=99999"), None);
}
