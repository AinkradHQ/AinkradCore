use super::*;
use crate::store::run_specs::spec::{Service, parse};

fn var(k: &str, v: &str) -> Var {
    Var {
        key: k.into(),
        value: Some(v.into()),
        secret: None,
    }
}

fn linked(k: &str, s: &str) -> Var {
    Var {
        key: k.into(),
        value: None,
        secret: Some(s.into()),
    }
}

fn cfg() -> Config {
    Config {
        id: 1,
        project_id: 1,
        name: "Dev server".into(),
        command: "npm run dev".into(),
        workdir: "./app".into(),
        runner: "automatic".into(),
        service: None,
        port: Some(3000),
        restart: false,
        position: 0,
        created_at: String::new(),
        updated_at: String::new(),
    }
}

fn spec() -> RunSpec {
    parse(&json!({"services": {
        "db": {"image": "postgres:17"},
        "web": {"image": "node:22", "repo": "web", "env": {"KEEP": "1"}}}}))
    .unwrap()
}

#[test]
fn dotenv_reads_quotes_comments_export_and_last_key_wins() {
    let p = parse_dotenv(
        "# c\nA=1\nexport B=\"two words\"\nC='x' \nD=v # note\nA=9\nbad line\n1X=2\nE=${HOME}\n",
    );
    assert_eq!(
        p.vars,
        vec![
            ("A".to_owned(), "9".to_owned()),
            ("B".to_owned(), "two words".to_owned()),
            ("C".to_owned(), "x".to_owned()),
            ("D".to_owned(), "v".to_owned()),
        ]
    );
    let lines: Vec<usize> = p.skipped.iter().map(|s| s.0).collect();
    assert_eq!(lines, vec![7, 8, 9]);
}

#[test]
fn diff_tells_same_different_and_one_sided() {
    let a = [
        var("A", "1"),
        var("B", "1"),
        linked("C", "db"),
        var("D", "x"),
    ];
    let b = [
        var("A", "1"),
        var("B", "2"),
        linked("C", "db"),
        var("E", "x"),
    ];
    let d = diff(&a, &b);
    let get = |k: &str| d.iter().find(|x| x.0 == k).unwrap().1;
    assert_eq!(get("A"), Change::Same);
    assert_eq!(get("B"), Change::Different);
    assert_eq!(get("C"), Change::Same);
    assert_eq!(get("D"), Change::OnlyA);
    assert_eq!(get("E"), Change::OnlyB);
    // a secret and a plain value of one key differ
    assert_eq!(
        diff(&[var("C", "db")], &[linked("C", "db")])[0].1,
        Change::Different
    );
}

#[test]
fn overlay_sets_command_folder_port_and_env_on_the_repo_service() {
    let mut s = spec();
    overlay(
        &mut s,
        &cfg(),
        &[var("API_URL", "http://x"), linked("DB", "database_url")],
    )
    .unwrap();
    let web: &Service = &s.services["web"];
    assert_eq!(web.command.as_deref().unwrap()[2], "npm run dev");
    assert_eq!(web.workdir.as_deref(), Some("/repo/web/app"));
    assert_eq!(web.ports[0].port, 3000);
    assert_eq!(web.env["KEEP"], "1");
    assert_eq!(web.env["DB"], "${secret:database_url}");
    assert!(
        s.services["db"].command.is_none(),
        "other services stay as they were"
    );
}

#[test]
fn overlay_refuses_a_plain_value_that_would_read_as_a_secret_ref() {
    assert!(value_problem("${secret:x}").is_some());
    let mut s = spec();
    let bad = Var {
        key: "A".into(),
        value: Some("${nope}".into()),
        secret: None,
    };
    assert!(overlay(&mut s, &cfg(), &[bad]).is_err());
}

#[test]
fn names_are_checked() {
    assert!(key_problem("API_URL").is_none());
    assert!(key_problem("1A").is_some());
    assert!(key_problem("A-B").is_some());
    assert!(key_problem("").is_some());
}
