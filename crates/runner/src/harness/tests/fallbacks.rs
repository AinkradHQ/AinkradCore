//! A run along its fallback chain (E15.3), against a fake `claude` that refuses some models:
//! an unavailable model moves the run to the next entry, which completes; a spent chain
//! fails with every reason; a permanent error fails at once.

use ainkrad_proto::runner::Route;

use super::*;

const FIXTURE: &str = include_str!("../../../../harness/tests/fixtures/claude/resume.ndjson");

/// A fake `claude`: `--model bad*` is refused as Claude refuses an unknown model, `--model
/// boom` fails for good, any other plays a recorded turn. Each start is logged with its model.
fn fake(dir: &Path) -> HarnessExecutor {
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let refused = serde_json::json!({"type": "result", "subtype": "success", "is_error": true,
        "api_error_status": 404, "usage": {}, "result": "There's an issue with the selected \
        model (MODEL). It may not exist or you may not have access to it."});
    let init = serde_json::json!({"type": "system", "subtype": "init", "session_id": "s"});
    std::fs::write(dir.join("refused.ndjson"), format!("{init}\n{refused}\n")).unwrap();
    let boom = serde_json::json!({"type": "result", "subtype": "error_during_execution",
        "is_error": true, "result": "boom", "usage": {}});
    std::fs::write(dir.join("boom.ndjson"), format!("{boom}\n")).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    let script = format!(
        "#!/bin/sh\nmodel=\nwhile [ $# -gt 0 ]; do [ \"$1\" = --model ] && model=$2; shift; done\n\
         echo \"$model\" >> {d}/models\nhead -n 2 > /dev/null\n\
         case $model in\n\
         bad*) sed \"s/MODEL/$model/\" {d}/refused.ndjson ;;\n\
         boom) cat {d}/boom.ndjson ;;\n\
         *) cat {d}/fixture.ndjson ;;\nesac\n"
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex
}

fn chain(model: &str, fallbacks: &[&str]) -> Job {
    Job {
        model: model.to_owned(),
        fallbacks: fallbacks
            .iter()
            .map(|m| Route {
                harness: "claude".to_owned(),
                model: (*m).to_owned(),
                account: None,
            })
            .collect(),
        ..job("claude")
    }
}

async fn work(ex: &HarnessExecutor, job: &Job) -> (Outcome, Vec<Report>) {
    ex.start(job).await.unwrap();
    let (tx, mut rx) = mpsc::channel(256);
    let outcome = ex.run(job, RunToken::new("t".to_owned()), tx).await;
    (outcome, std::iter::from_fn(|| rx.try_recv().ok()).collect())
}

fn fallbacks(reports: &[Report]) -> Vec<(String, String)> {
    reports
        .iter()
        .filter_map(|r| match r {
            Report::Fallback { model, class, .. } => Some((model.clone(), class.clone())),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn an_unavailable_model_falls_back_and_the_run_completes() {
    let dir = scratch("fallback");
    let ex = fake(&dir);
    let (outcome, reports) = work(&ex, &chain("bad-opus", &["bad-sonnet", "haiku"])).await;
    assert_eq!(outcome, Outcome::Succeeded);
    assert_eq!(
        fallbacks(&reports),
        [
            ("bad-sonnet".to_owned(), "model_unavailable".to_owned()),
            ("haiku".to_owned(), "model_unavailable".to_owned())
        ]
    );
    let models = std::fs::read_to_string(dir.join("models")).unwrap();
    assert_eq!(models, "bad-opus\nbad-sonnet\nhaiku\n");
    // The run's usage keeps adding up across entries: the last report is the haiku turn's.
    let last = reports.iter().rev().find_map(|r| match r {
        Report::Usage(u) => Some(*u),
        _ => None,
    });
    assert!(last.unwrap().sum() > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_spent_chain_fails_with_every_reason_and_a_permanent_error_fails_at_once() {
    let dir = scratch("fallback-spent");
    let ex = fake(&dir);
    let (outcome, _) = work(&ex, &chain("bad-a", &["bad-b"])).await;
    let Outcome::Failed {
        reason,
        fingerprint,
    } = outcome
    else {
        panic!("{outcome:?}");
    };
    assert_eq!(fingerprint.as_deref(), Some("fallback_exhausted"));
    assert!(
        reason.starts_with("every model in the fallback chain failed: claude/bad-a: model_unavailable: There's an issue with the selected model (bad-a)"),
        "{reason}"
    );
    assert!(
        reason.contains("; claude/bad-b: model_unavailable: "),
        "{reason}"
    );

    let (outcome, reports) = work(&ex, &chain("boom", &["haiku"])).await;
    assert!(
        matches!(&outcome, Outcome::Failed { reason, .. } if reason == "boom"),
        "{outcome:?}"
    );
    assert!(
        fallbacks(&reports).is_empty(),
        "no fallback for a permanent error"
    );
    // Alone, an unavailable model fails as itself, not as a spent chain.
    let (outcome, _) = work(&ex, &chain("bad-z", &[])).await;
    assert!(
        matches!(&outcome, Outcome::Failed { fingerprint: Some(f), .. } if f == "claude:success:404"),
        "{outcome:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An entry whose account token cannot be read is skipped: the next one takes the run, and
/// the server hears why the entry that ran failed.
#[tokio::test]
async fn an_entry_without_its_token_is_skipped() {
    let dir = scratch("fallback-token");
    let ex = fake(&dir);
    let mut job = chain("bad-opus", &["sonnet", "haiku"]);
    job.fallbacks[0].account = Some(ainkrad_proto::runner::Account {
        id: 9,
        label: "gone".to_owned(),
        config_dir: "accounts/gone".to_owned(),
        credential_ref: Some("gone.token".to_owned()),
        credential_env: Some("CLAUDE_CODE_OAUTH_TOKEN".to_owned()),
    });
    let (outcome, reports) = work(&ex, &job).await;
    assert_eq!(outcome, Outcome::Succeeded);
    assert_eq!(
        fallbacks(&reports),
        [("haiku".to_owned(), "model_unavailable".to_owned())]
    );
    let models = std::fs::read_to_string(dir.join("models")).unwrap();
    assert_eq!(models, "bad-opus\nhaiku\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_class_the_server_turns_off_fails_the_run_where_it_is() {
    let dir = scratch("fallback-off");
    let ex = fake(&dir);
    let limits = ainkrad_proto::runner::RunLimits {
        approval_timeout_secs: 60,
        max_resumes: 0,
        resume_backoff_ms: 10,
        resume_backoff_max_ms: 10,
        warm_max: 0,
        stall_after_secs: 600,
        tool_output_bytes: 2048,
        fallback_on_model_unavailable: false,
        fallback_on_rate_limited: true,
        fallback_on_quota: true,
        fallback_on_unhealthy: true,
    };
    let job = Job {
        limits: Some(limits),
        ..chain("bad-opus", &["haiku"])
    };
    let (outcome, reports) = work(&ex, &job).await;
    assert!(matches!(outcome, Outcome::Failed { .. }), "{outcome:?}");
    assert!(fallbacks(&reports).is_empty());
    let models = std::fs::read_to_string(dir.join("models")).unwrap();
    assert_eq!(models, "bad-opus\n", "never the next entry");
    let _ = std::fs::remove_dir_all(&dir);
}
