//! `job.run`'s checks, redaction, sandbox contract and environment, without a sandbox (the end-to-end
//! run needs bubblewrap or Seatbelt and is the epic's E2E, spec §11).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{ErrorCode, JOB_REGISTRY_HOSTS, JobNeed, JobRun, RunSecret};

use super::prep::{
    command_env, problem, redact_chunk, sandbox_vars, signal_name, signal_number, within,
};
use crate::v2::toolchains;

fn req() -> JobRun {
    JobRun {
        job: "j_abc123".into(),
        project: 4,
        cache: "core".into(),
        argv: vec!["cargo".into(), "build".into()],
        cwd_rel: "crates/app".into(),
        need: JobNeed::default(),
        ..JobRun::default()
    }
}

fn refused(r: &JobRun) -> Option<ErrorCode> {
    problem(r).map(|e| e.code)
}

#[test]
fn a_sound_request_passes_and_the_unsound_ones_are_refused() {
    assert_eq!(refused(&req()), None);
    let mut r = req();
    r.argv.clear();
    assert_eq!(refused(&r), Some(ErrorCode::InvalidArgs));
    let mut r = req();
    r.argv[1] = "a\0b".into();
    assert_eq!(refused(&r), Some(ErrorCode::InvalidArgs));
    for bad in ["../x", "/etc", "a/../b", ".git/hooks", "a\\b"] {
        let mut r = req();
        r.cwd_rel = bad.into();
        assert_eq!(refused(&r), Some(ErrorCode::PathRefused), "{bad}");
    }
    let mut r = req();
    r.job = "../j".into();
    assert_eq!(refused(&r), Some(ErrorCode::InvalidArgs));
    let mut r = req();
    r.cache = "a/b".into();
    assert_eq!(refused(&r), Some(ErrorCode::InvalidArgs));
    let mut r = req();
    r.timeout_ms = Some(0);
    assert_eq!(refused(&r), Some(ErrorCode::InvalidArgs));
}

#[test]
fn a_job_may_not_set_loader_or_ainkrad_variables_or_repeat_a_secret() {
    for name in [
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "AINKRAD_SANDBOX_NETWORK",
        "lower",
        "A-B",
    ] {
        let mut r = req();
        r.env = BTreeMap::from([(name.to_owned(), "x".to_owned())]);
        assert_eq!(refused(&r), Some(ErrorCode::InvalidArgs), "{name}");
    }
    let mut r = req();
    r.env = BTreeMap::from([("NODE_ENV".to_owned(), "test".to_owned())]);
    assert_eq!(refused(&r), None);
    r.secrets = vec![
        RunSecret {
            name: "NPM_TOKEN".into(),
            lease: "l_1".into(),
        },
        RunSecret {
            name: "NPM_TOKEN".into(),
            lease: "l_2".into(),
        },
    ];
    assert_eq!(refused(&r), Some(ErrorCode::InvalidArgs));
}

#[test]
fn the_working_folder_must_be_inside_the_project_even_through_a_link() {
    let base = std::env::temp_dir().join(format!("job-within-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (root, outside) = (base.join("root"), base.join("outside"));
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
    assert!(within(&root, &root));
    assert!(within(&root, &root.join("sub")));
    assert!(!within(&root, &root.join("escape")));
    assert!(!within(&root, &root.join("missing")));
    assert!(!within(&root, &root.join("sub/../../outside")));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_secret_is_masked_even_when_a_read_cuts_it_or_a_character() {
    let mut r = Redactor::new();
    r.known("NPM_TOKEN", "sekret-value-123456");
    let mut carry = Vec::new();
    let mut all = Vec::new();
    for chunk in [
        &b"token=sekret-val"[..],
        &b"ue-123456 and caf\xc3"[..],
        &b"\xa9 done"[..],
    ] {
        all.extend(redact_chunk(&mut r, &mut carry, chunk));
    }
    let text = String::from_utf8(all).unwrap();
    assert!(!text.contains("sekret"), "{text}");
    assert!(text.contains("[redacted:NPM_TOKEN]"), "{text}");
    assert!(text.contains("café done"), "{text}");
    assert!(carry.is_empty());
}

#[test]
fn bytes_that_are_not_utf8_become_replacement_characters_not_a_stall() {
    let mut r = Redactor::new();
    let mut carry = Vec::new();
    let out = redact_chunk(&mut r, &mut carry, b"ok \xff\xfe end");
    assert_eq!(String::from_utf8(out).unwrap(), "ok \u{fffd}\u{fffd} end");
    assert!(carry.is_empty());
}

#[test]
fn signals_have_names_both_ways() {
    assert_eq!(signal_name(9), "KILL");
    assert_eq!(signal_name(15), "TERM");
    assert_eq!(signal_name(31), "SIG31");
    assert_eq!(signal_number("INT"), Some(2));
    assert_eq!(signal_number("KILL"), Some(9));
    assert_eq!(
        signal_number("STOP"),
        None,
        "only the four a job may be sent"
    );
}

fn value<'a>(env: &'a [(String, OsString)], name: &str) -> Option<&'a OsString> {
    env.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v)
}

#[test]
fn the_sandbox_is_filtered_with_toolchains_read_only_and_build_sized_limits() {
    let proxy = vec![(
        "AINKRAD_SANDBOX_EGRESS_SOCK".to_owned(),
        OsString::from("/j/egress/egress.sock"),
    )];
    let v = sandbox_vars(
        Path::new("/state"),
        Path::new("/state/jobs/j1"),
        &[
            PathBuf::from("/state/toolchains/rust/1.100.0"),
            PathBuf::from("/state/toolchains/node/22.22.1"),
        ],
        Duration::from_secs(90),
        proxy,
    );
    assert_eq!(value(&v, "AINKRAD_SANDBOX_NETWORK").unwrap(), "filtered");
    assert_eq!(value(&v, "AINKRAD_SANDBOX").unwrap(), "1");
    assert_eq!(
        value(&v, "AINKRAD_SANDBOX_RO").unwrap(),
        "/state/toolchains/rust/1.100.0:/state/toolchains/node/22.22.1"
    );
    assert_eq!(value(&v, "AINKRAD_SANDBOX_WALL").unwrap(), "90");
    assert_eq!(value(&v, "AINKRAD_SANDBOX_PROCESSES").unwrap(), "4096");
    assert!(value(&v, "AINKRAD_SANDBOX_EGRESS_SOCK").is_some());
    assert_eq!(
        value(&v, "AINKRAD_SANDBOX_TMP").unwrap(),
        "/state/jobs/j1/tmp"
    );
}

#[test]
fn the_command_starts_with_an_empty_environment_plus_only_what_the_job_set() {
    let tools = toolchains::JobTools {
        ro: vec![],
        path: vec![PathBuf::from("/tc/node/bin")],
        env: vec![("npm_config_cache".to_owned(), "/h/npm".to_owned())],
    };
    let mut r = req();
    r.env = BTreeMap::from([("NODE_ENV".to_owned(), "test".to_owned())]);
    let env = command_env(
        Path::new("/h"),
        Path::new("/t"),
        &tools,
        Some("abc123"),
        &r,
        &[("NPM_TOKEN".to_owned(), "tok".to_owned())],
    );
    let names: Vec<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
    for n in &names {
        assert!(
            [
                "PATH",
                "HOME",
                "TMPDIR",
                "LANG",
                "CI",
                "AINKRAD_GIT_HEAD",
                "npm_config_cache",
                "NODE_ENV",
                "NPM_TOKEN"
            ]
            .contains(n),
            "{n} is not something the job was given"
        );
    }
    assert_eq!(value(&env, "HOME").unwrap(), "/h");
    assert_eq!(value(&env, "AINKRAD_GIT_HEAD").unwrap(), "abc123");
    assert!(
        value(&env, "PATH")
            .unwrap()
            .to_string_lossy()
            .starts_with("/tc/node/bin:")
    );
    assert_eq!(names.last(), Some(&"NPM_TOKEN"), "secrets are set last");
}

#[test]
fn the_registry_list_is_the_one_the_spec_names() {
    assert_eq!(
        JOB_REGISTRY_HOSTS.to_vec(),
        [
            "crates.io",
            "static.crates.io",
            "registry.npmjs.org",
            "pypi.org",
            "files.pythonhosted.org",
            "proxy.golang.org",
        ]
    );
}
