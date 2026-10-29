//! E15.16's acceptance, with a fake GitHub and a fake GitLab in one project: an issue touching
//! two repos gets two worktrees and two PRs, one QA pass and one `pr_merge` approval, merges in
//! the project's repo order and is done only after both; a second merge that fails leaves the
//! first merged, keeps the issue in review and opens the approval again with the reason; a repo
//! an agent asks for mid-task, once its team lead approves, is a worktree of its next run.

use std::path::PathBuf;

use ainkrad_core::gov::{ApprovalKind, ApprovalStatus};
use ainkrad_core::work::{IssueId, IssueState, NextActor, ProjectId, ProjectMode};
use ainkrad_core_server::store::forge::{PrPhase, ProjectForge, issue_prs};
use ainkrad_core_server::store::gov::{decide_approval, list_approvals};
use ainkrad_core_server::store::work::{Commands, Repo, add_repo, get_issue, set_issue_repos};
use ainkrad_providers::Kind;
use ainkrad_providers::fake::{Hub, Shared};
use serde_json::{Value, json};

use super::forges::{forge, set_checks_on};
use super::stage::{ADMIN, Org, Stage, git};
use ainkrad_core::audit::AuditActor;

/// A bare repo `<name>.git` with one commit on `main`.
fn origin(stage: &Stage, name: &str) -> PathBuf {
    let seed = stage.dir.join(format!("seed-{name}"));
    std::fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    std::fs::write(seed.join("README.md"), format!("{name}\n")).unwrap();
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-qm", "init"]);
    let bare = format!("{name}.git");
    git(
        &stage.dir,
        &["clone", "-q", "--bare", &format!("seed-{name}"), &bare],
    );
    stage.dir.join(bare)
}

/// The two forges: `core` on GitHub (primary), `plugin` on GitLab.
struct Two {
    project: ProjectId,
    hub: Shared<Hub>,
    lab: Shared<Hub>,
    core: PathBuf,
    plugin: PathBuf,
}

async fn two_repos(stage: &Stage, o: &Org, key: &str) -> Two {
    let project = stage.project(o, key, ProjectMode::Kanban).await;
    let token_file = stage.dir.join("forge-token");
    std::fs::write(&token_file, "forge_token\n").unwrap();
    let mut out = vec![];
    for (name, kind) in [("core", Kind::GitHub), ("plugin", Kind::GitLab)] {
        let (api, hub) = forge(kind).await;
        let url = origin(stage, name);
        hub.lock().unwrap().git = Some(url.clone());
        let r = Repo {
            id: 0,
            project_id: project,
            name: name.to_owned(),
            url: url.display().to_string(),
            default_branch: "main".to_owned(),
            position: 0,
            primary: false,
            forge: Some(ProjectForge {
                project_id: project,
                kind,
                api_url: api,
                repo: format!("acme/{name}"),
                token_file: token_file.clone(),
            }),
            commands: Commands {
                test: format!("make -C {name} test"),
                ..Commands::default()
            },
        };
        let by = AuditActor::User(ADMIN);
        let added = add_repo(&stage.pool, &r, by).await.unwrap().unwrap();
        assert_eq!(added.primary, name == "core");
        out.push((hub, url));
    }
    let (plugin_hub, plugin) = out.pop().unwrap();
    let (core_hub, core) = out.pop().unwrap();
    Two {
        project,
        hub: core_hub,
        lab: plugin_hub,
        core,
        plugin,
    }
}

/// The developer works `issue` in both repos: a commit in each, a PR on each, done; then the
/// checks pass, the poller opens both and QA passes it. The approval's id and payload.
async fn develop_and_pass(stage: &mut Stage, o: &Org, t: &Two, issue: IssueId) -> (i64, Value) {
    let key = stage.key(issue).await;
    let n = stage
        .play(
            issue,
            &[
                ("transition", json!({"transition": "start"})),
                ("open_pr", json!({"title": format!("{key}: Both")})),
                (
                    "open_pr",
                    json!({"title": format!("{key}: Both"), "repo": "core"}),
                ),
                (
                    "open_pr",
                    json!({"title": format!("{key}: Both"), "repo": "plugin"}),
                ),
                ("transition", json!({"transition": "done"})),
            ],
        )
        .await;
    let commit = |d: &str| {
        format!("(cd {d} && echo {key} > {key}.txt && git add -A && git commit -qm {key})")
    };
    let sh = format!("ls && {} && {}", commit("core"), commit("plugin"));
    stage.script(issue, n, &sh).await;
    // QA is woken by the done, before the PRs are open: its pass is refused.
    let pass = [(
        "qa_verdict",
        json!({"verdict": "pass", "notes": "Both fine"}),
    )];
    let early = stage.play(issue, &pass).await;
    stage.assign(issue, o.dev).await;
    assert_eq!(stage.ended(issue, n as i64).await, "succeeded");
    stage.ended(issue, early as i64).await;
    let refused = &stage.replies(issue, early).await[0];
    let refused = refused["error"].as_str().unwrap_or_default();
    assert!(refused.contains("the core PR is not open yet"), "{refused}");
    let replies = stage.replies(issue, n).await;
    assert!(
        replies[1]["error"]
            .as_str()
            .unwrap()
            .contains("name one: core, plugin"),
        "{replies:?}"
    );
    assert_eq!(replies[2]["state"], "requested", "{replies:?}");
    assert_eq!(replies[3]["state"], "requested", "{replies:?}");
    assert_eq!(replies[4]["state"], "in_review", "{replies:?}");
    let told = stage.instructions(issue, n).await;
    assert!(
        told.contains("## repositories\n\n- core (primary): "),
        "{told}"
    );
    assert!(told.contains("  - test: `make -C plugin test`\n"), "{told}");

    // One branch name, pushed to both origins; checks pass on both heads.
    let branch = format!("refs/heads/citadel/{key}");
    let core_sha = git(&t.core, &["rev-parse", &branch]);
    let plugin_sha = git(&t.plugin, &["rev-parse", &branch]);
    set_checks_on(Kind::GitHub, &t.hub, core_sha.trim(), "success");
    set_checks_on(Kind::GitLab, &t.lab, plugin_sha.trim(), "success");
    let q = stage.play(issue, &pass).await;
    stage.poll().await;
    stage.ended(issue, q as i64).await;
    let passed = &stage.replies(issue, q).await[0];
    assert_eq!(passed["verdict"], "pass", "{passed}");
    let id = passed["approval_id"].as_i64().unwrap();
    let a = list_approvals(&stage.pool, o.company).await.unwrap();
    let a = a.into_iter().find(|a| a.id.0 == id).unwrap();
    assert_eq!(
        (a.kind, a.status),
        (ApprovalKind::PrMerge, ApprovalStatus::Pending)
    );
    (id, serde_json::from_str(&a.payload).unwrap())
}

async fn states(stage: &Stage, issue: IssueId) -> Vec<PrPhase> {
    let prs = issue_prs(&stage.pool, issue).await.unwrap();
    prs.iter().map(|p| p.phase).collect()
}

async fn waits_on(stage: &Stage, issue: IssueId) -> (IssueState, Option<NextActor>) {
    let i = get_issue(&stage.pool, issue).await.unwrap().unwrap();
    (i.state, i.next_actor)
}

async fn approve(stage: &Stage, id: i64) {
    let id = ainkrad_core::gov::ApprovalId(id);
    decide_approval(&stage.pool, id, true, ADMIN, None, &stage.now())
        .await
        .unwrap();
}

#[tokio::test]
async fn two_repos_two_worktrees_two_prs_one_approval_merged_in_order() {
    let mut stage = Stage::new("multi-repo").await;
    let o = stage.org().await;
    let t = two_repos(&stage, &o, "MR").await;
    let issue = stage.issue(t.project, "Both", None).await;
    let names = ["core".to_owned(), "plugin".to_owned()];
    let by = AuditActor::User(ADMIN);
    set_issue_repos(&stage.pool, issue, &names, by)
        .await
        .unwrap();

    let (id, payload) = develop_and_pass(&mut stage, &o, &t, issue).await;
    let tree = stage.dir.join(format!("work/worktrees/issue-{}", issue.0));
    assert!(tree.join("core/.git").is_file() && tree.join("plugin/.git").is_file());
    let listed = std::fs::read_to_string(stage.dir.join("plays/MR-1.1.sh.out")).unwrap();
    assert_eq!(
        listed.lines().collect::<Vec<_>>(),
        ["core", "plugin"],
        "two worktrees"
    );
    assert_eq!(payload["prs"].as_array().unwrap().len(), 2, "{payload}");
    assert_eq!(payload["prs"][0]["repo"], "core");
    assert!(
        payload["summary"]
            .as_str()
            .unwrap()
            .starts_with("Merge 2 PRs (core PR #1, plugin PR #1)")
    );
    assert_eq!(states(&stage, issue).await, [PrPhase::Open, PrPhase::Open]);

    approve(&stage, id).await;
    stage.poll().await;
    assert_eq!(t.hub.lock().unwrap().merges, [(1, "merge".to_owned())]);
    assert_eq!(t.lab.lock().unwrap().merges, [(1, "merge".to_owned())]);
    let merged: Vec<i64> = sqlx::query_scalar(
        "SELECT json_extract(details, '$.repo') FROM audit_events WHERE action = 'pr.merged' \
         ORDER BY seq",
    )
    .fetch_all(&stage.pool)
    .await
    .unwrap();
    let ids: Vec<i64> = issue_prs(&stage.pool, issue)
        .await
        .unwrap()
        .iter()
        .map(|p| p.repo_id)
        .collect();
    assert_eq!(merged, ids, "core, then plugin");
    assert_eq!(
        waits_on(&stage, issue).await,
        (IssueState::Done, None),
        "done after both"
    );
}

#[tokio::test]
async fn a_failed_second_merge_reopens_the_approval_and_keeps_the_first() {
    let mut stage = Stage::new("multi-repo-fail").await;
    let o = stage.org().await;
    let t = two_repos(&stage, &o, "MF").await;
    let issue = stage.issue(t.project, "Both", None).await;
    let names = ["core".to_owned(), "plugin".to_owned()];
    set_issue_repos(&stage.pool, issue, &names, AuditActor::User(ADMIN))
        .await
        .unwrap();
    let (id, _) = develop_and_pass(&mut stage, &o, &t, issue).await;

    t.lab.lock().unwrap().unmergeable.push(1);
    approve(&stage, id).await;
    stage.poll().await;
    assert_eq!(t.hub.lock().unwrap().merges.len(), 1, "core merged");
    assert!(t.lab.lock().unwrap().merges.is_empty());
    assert_eq!(
        states(&stage, issue).await,
        [PrPhase::Merged, PrPhase::Open]
    );
    assert_eq!(
        waits_on(&stage, issue).await,
        (IssueState::InReview, Some(NextActor::Human(ADMIN))),
        "stays in review"
    );
    let all = list_approvals(&stage.pool, o.company).await.unwrap();
    let again = all
        .iter()
        .find(|a| a.status == ApprovalStatus::Pending)
        .expect("reopened");
    let payload: Value = serde_json::from_str(&again.payload).unwrap();
    assert_eq!(payload["reopened_from"], id, "{payload}");
    assert!(
        payload["summary"]
            .as_str()
            .unwrap()
            .contains("plugin PR #1"),
        "{payload}"
    );
    assert!(!payload["reason"].as_str().unwrap().is_empty());

    // Fixed on the forge and approved again: the rest merges, and the issue is done.
    t.lab.lock().unwrap().unmergeable.clear();
    approve(&stage, again.id.0).await;
    stage.poll().await;
    assert_eq!(t.hub.lock().unwrap().merges.len(), 1, "core left alone");
    assert_eq!(t.lab.lock().unwrap().merges.len(), 1);
    assert_eq!(waits_on(&stage, issue).await, (IssueState::Done, None));
}

#[tokio::test]
async fn a_repo_asked_for_mid_task_is_a_worktree_once_the_lead_approves() {
    let mut stage = Stage::new("multi-repo-ask").await;
    let o = stage.org().await;
    let t = two_repos(&stage, &o, "MA").await;
    let issue = stage.issue(t.project, "Needs the plugin too", None).await;
    let ask = json!({"repo": "plugin", "reason": "The client must change too"});
    stage
        .play(issue, &[("request_repo", ask), ("get_issue", json!({}))])
        .await;
    stage.script(issue, 1, "ls -a").await;
    // The lead is woken and approves; the developer is woken with the answer.
    let decide = json!({"repo": "plugin", "verdict": "approve", "reason": "Yes"});
    stage.play(issue, &[("decide_repo", decide)]).await;
    let start = ("transition", json!({"transition": "start"}));
    stage.play(issue, &[("get_issue", json!({})), start]).await;
    stage.script(issue, 3, "ls").await;
    stage.assign(issue, o.dev).await;
    assert_eq!(stage.ended(issue, 1).await, "succeeded");
    let asked = stage.replies(issue, 1).await;
    assert_eq!(asked[0]["status"], "requested", "{asked:?}");
    assert_eq!(asked[1]["repo_requests"][0]["repo"], "plugin", "{asked:?}");
    let first = std::fs::read_to_string(stage.dir.join("plays/MA-1.1.sh.out")).unwrap();
    assert!(
        first.contains("README.md") && !first.contains("plugin"),
        "{first}"
    );

    assert_eq!(stage.ended(issue, 3).await, "succeeded");
    let decided = &stage.replies(issue, 2).await[0];
    assert_eq!(decided["status"], "approved", "{decided}");
    let agents: Vec<i64> =
        sqlx::query_scalar("SELECT agent_id FROM runs WHERE issue_id = ? ORDER BY id")
            .bind(issue.0)
            .fetch_all(&stage.pool)
            .await
            .unwrap();
    assert_eq!(agents, [o.dev.0, o.lead.0, o.dev.0]);
    let after = std::fs::read_to_string(stage.dir.join("plays/MA-1.3.sh.out")).unwrap();
    assert_eq!(
        after.lines().collect::<Vec<_>>(),
        ["core", "plugin"],
        "{after}"
    );
    let now = &stage.replies(issue, 3).await[0];
    let repos: Vec<&str> = now["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(repos, ["core", "plugin"]);
}
