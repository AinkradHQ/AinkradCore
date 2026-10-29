//! The plan build through the run's `citadel` CLI (E15.18 step 3): two shell commands, each a
//! model turn. The first reads what the plan needs (the issue, the project, the org, and the
//! `apply_plan` line of `citadel schema`) in one batch, filtered to a few lines; the second files
//! the plan from stdin and prints only its outcome. Only those outputs return to the model.
//!
//! A `curl` shim first on the script's `PATH` records every argv and environment the CLI runs
//! curl with: the run token is in neither.

use ainkrad_core::work::IssueId;
use serde_json::Value;

use super::super::stage::{Org, Stage};
use super::{Usage, apply_call, defs_bytes, list_request, run_numbers};

/// Turn 1: the reads, in one command, filtered.
const READ: &str = r#"citadel schema | grep -o '"apply_plan":"[^"]*"'
printf '[{"op":"get_issue"},{"op":"get_context"},{"op":"org_chart"}]' | citadel batch | perl -MJSON::PP -0777 -ne '
my $r = decode_json($_)->{results};
print encode_json({issue => $r->[0]{title}, body => $r->[0]{body},
    spec => $r->[1]{project}{spec},
    agents => [map { "$_->{id}:$_->{role}" } @{$r->[2]{agents} || []}]}), "\n"'"#;

/// Turn 2: the plan from stdin; only its outcome is printed.
fn apply(plan: &Value) -> String {
    format!(
        "citadel apply_plan - <<'PLAN' | perl -MJSON::PP -0777 -ne '\n\
         my $r = decode_json($_);\n\
         print encode_json({{tasks => scalar @{{$r->{{tasks}}}}, sprint => $r->{{sprint_id}},\n\
             problems => $r->{{problems}}, state => $r->{{state}}}}), \"\\n\"'\n\
         {plan}\nPLAN"
    )
}

/// The `curl` shim: records its argv and environment, then runs the real one.
const SHIM: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "__DIR__/curl.argv"
env >> "__DIR__/curl.env"
exec /usr/bin/curl "$@"
"#;

pub async fn cli_session(stage: &mut Stage, o: &Org, kickoff: IssueId) -> Usage {
    let plays = stage.dir.join("plays");
    let shim = stage.dir.join("shim");
    std::fs::create_dir_all(&shim).unwrap();
    let curl = shim.join("curl");
    std::fs::write(
        &curl,
        SHIM.replace("__DIR__", &stage.dir.display().to_string()),
    )
    .unwrap();
    std::fs::set_permissions(&curl, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    // Its first run (macOS checks a new executable once) is not the agent's.
    let warm = std::process::Command::new(&curl)
        .arg("--version")
        .output()
        .unwrap();
    assert!(warm.status.success());
    for log in ["curl.argv", "curl.env"] {
        std::fs::write(stage.dir.join(log), "").unwrap();
    }
    let commands = [
        READ.to_owned(),
        apply(&apply_call(o)["params"]["arguments"]),
    ];
    let n = stage.play_requests("EXP-1", &[list_request()]);
    let mut sh = format!("export PATH='{}':\"$PATH\"\n", shim.display());
    for (i, c) in commands.iter().enumerate() {
        let out = plays.join(format!("cli.{i}.out"));
        sh += &format!("{{\n{c}\n}} > '{}' 2>&1\n", out.display());
    }
    stage.script_key("EXP-1", n, &sh);
    stage.wake(kickoff, o.po).await;
    assert_eq!(stage.ended(kickoff, n as i64).await, "succeeded");

    let replies = stage.raw_replies("EXP-1", n);
    let mut u = Usage {
        defs: defs_bytes(&replies[0]),
        ..Usage::default()
    };
    for (i, c) in commands.iter().enumerate() {
        let out = std::fs::read_to_string(plays.join(format!("cli.{i}.out"))).unwrap();
        assert!(!out.contains("\"error\""), "turn {i}: {out}");
        u.turns += 1;
        u.wrote += c.len();
        u.read += out.len();
        u.per_turn.push(c.len() + out.len());
    }
    let outcome = std::fs::read_to_string(plays.join("cli.1.out")).unwrap();
    assert!(outcome.contains("\"tasks\":9"), "{outcome}");
    run_numbers(stage, kickoff, n, &mut u).await;

    // The token never on curl's argv nor in the environment the CLI runs it with.
    let argv = std::fs::read_to_string(stage.dir.join("curl.argv")).unwrap();
    let env = std::fs::read_to_string(stage.dir.join("curl.env")).unwrap();
    assert_eq!(argv.lines().count(), 3, "schema, batch, apply_plan: {argv}");
    assert!(argv.contains("-K /dev/fd/3"), "{argv}");
    for (what, text) in [("argv", &argv), ("env", &env)] {
        assert!(
            !text.contains("cit_run_"),
            "the run token is in curl's {what}"
        );
    }
    u
}
