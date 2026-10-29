//! A whole company on one machine, for end-to-end flows: the server in-process on a loopback
//! port, a real runner (`HarnessExecutor`) and one fake `claude` every agent runs as. The fake
//! plays a script per run: `plays/<KEY>.<n>` (the n-th run on issue KEY) holds JSON-RPC tool
//! calls, one per line, which it sends to `/mcp/v1` with the run's token; the replies land in
//! `<KEY>.<n>.out`, the run's instructions in `<KEY>.<n>.instructions` and its prompt (as
//! Claude's stdin carried it) in `<KEY>.<n>.prompt`. A shell script
//! `<KEY>.<n>.sh`, if any, runs first in the run's working dir (to commit work). Then it plays a
//! recorded Claude turn, so the run succeeds. The test writes each play before it hands the
//! issue to the agent, so what every agent does is deterministic.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use citadel_core::audit::AuditActor;
use citadel_core::exec::NewRunner;
use citadel_core::org::{AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole, TeamId};
use citadel_core::work::{
    IssueId, IssueKind, IssueState, IssueTransition, NewIssue, NewProject, NextActor, ProjectId,
    ProjectMode, ProjectRepo, SprintApproval, SprintId, UserId,
};
use citadel_server::api::{App, router};
use citadel_server::scheduler::{Clock, SystemClock};
use citadel_server::store::{self, exec, forge, gov, org, work};
use ainkrad_harness::claude;
use ainkrad_providers::Kind;
use ainkrad_runner::{Config, HarnessExecutor, mcp_url};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tokio::task::JoinHandle;

pub const ADMIN: UserId = UserId(1);
const RESULT: &str = include_str!("../../../../../crates/harness/tests/fixtures/claude/resume.ndjson");

/// The fake `claude`: finds its MCP config, instructions and issue key, plays the run's
/// script, then a recorded turn.
const FAKE: &str = r#"#!/bin/sh
d=__DIR__
while [ $# -gt 0 ]; do
    case "$1" in
    --mcp-config) cfg=$2 ;;
    --append-system-prompt-file) ins=$2 ;;
    esac
    shift
done
field() { perl -MJSON::PP -0777 -ne "print decode_json(\$_)->{mcpServers}{citadel}$1" "$cfg"; }
url=$(field '{url}')
auth=$(field '{headers}{Authorization}')
prompt=$(head -n 2)
key=$(printf '%s' "$prompt" | grep -oE ' on [A-Z][A-Z0-9]*-[0-9]+' | head -n 1 | cut -c5-)
n=$(cat "$d/plays/$key.n" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$d/plays/$key.n"
[ -n "$ins" ] && cp "$ins" "$d/plays/$key.$n.instructions"
printf '%s\n' "$prompt" > "$d/plays/$key.$n.prompt"
[ -f "$d/plays/$key.$n.sh" ] && sh "$d/plays/$key.$n.sh" >> "$d/plays/$key.$n.sh.out" 2>&1
if [ -f "$d/plays/$key.$n" ]; then
    while IFS= read -r body; do
        printf 'Authorization: %s\n' "$auth" | curl -sS -H @- \
            -H 'Content-Type: application/json' \
            -H 'Accept: application/json, text/event-stream' \
            --data "$body" "$url" >> "$d/plays/$key.$n.out"
        echo >> "$d/plays/$key.$n.out"
    done < "$d/plays/$key.$n"
fi
cat "$d/result.ndjson"
"#;

/// The Engineering template's company, every hire approved.
pub struct Org {
    pub company: CompanyId,
    pub team: TeamId,
    pub ceo: AgentId,
    pub cto: AgentId,
    pub po: AgentId,
    pub lead: AgentId,
    pub dev: AgentId,
    pub qa: AgentId,
}

pub struct Stage {
    pub dir: PathBuf,
    pub db: PathBuf,
    pub pool: SqlitePool,
    /// The server's base URL, `http://127.0.0.1:<port>`.
    pub base: String,
    /// Runs played so far per issue key.
    runs: HashMap<String, u32>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Stage {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

impl Stage {
    /// A fresh database, the server serving it, and a runner whose `claude` is the fake.
    pub async fn new(name: &str) -> Self {
        Self::with(name, |_| {}).await
    }

    /// `new`, letting `tune` adjust the runner's executor before it starts.
    pub async fn with(name: &str, tune: impl FnOnce(&mut HarnessExecutor)) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("citadel-co-{name}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(dir.join("plays")).unwrap();
        // Real paths: macOS's `/var` is `/private/var`, and git records real paths.
        let dir = dir.canonicalize().unwrap();
        let db = dir.join("citadel.db");
        let pool = store::connect(&db).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        let app = App::new(pool.clone(), Arc::new(SystemClock), host.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router(app)).await;
        });

        std::fs::write(dir.join("result.ndjson"), RESULT).unwrap();
        let fake = dir.join("claude");
        std::fs::write(&fake, FAKE.replace("__DIR__", &dir.display().to_string())).unwrap();
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let new = NewRunner {
            name: "box".to_owned(),
            tags: vec![],
        };
        let (_, key) = exec::register_runner(&pool, &new).await.unwrap();
        let url = format!("ws://{host}/runner/v1/connect");
        let mut executor = HarnessExecutor::new(dir.join("work"), dir.join("config"));
        executor.bins.insert("claude".to_owned(), fake);
        executor.mcp_url = mcp_url(&url);
        executor.usage_every = Duration::from_millis(200);
        tune(&mut executor);
        executor
            .workspaces
            .set_identity(Some("Citadel Test"), Some("test@citadel.invalid"))
            .await
            .unwrap();
        let mut harnesses: std::collections::BTreeMap<String, String> =
            [("claude".to_owned(), claude::VERSION.to_owned())].into();
        harnesses.insert(
            "opencode".to_owned(),
            ainkrad_harness::opencode::VERSION.to_owned(),
        );
        let config = Config {
            log: None,
            url,
            key,
            tags: vec![],
            harnesses,
        };
        let runner = tokio::spawn(async move {
            ainkrad_runner::run(config, executor).await;
        });
        Self {
            base: format!("http://{host}"),
            dir,
            db,
            pool,
            runs: HashMap::new(),
            tasks: vec![server, runner],
        }
    }

    pub fn now(&self) -> String {
        SystemClock.now()
    }

    /// A company with an active CEO and the Engineering template, every hire approved.
    pub async fn org(&self) -> Org {
        let pool = &self.pool;
        let company = org::create_company(pool, "Acme").await.unwrap().id;
        let by = AuditActor::User(ADMIN);
        let ceo = NewAgent {
            company_id: company,
            name: "CEO".to_owned(),
            role: "CEO".to_owned(),
            org_role: OrgRole::Ceo,
            reports_to: None,
            harness: Harness::Claude,
            model: "opus".to_owned(),
            runner_tags: vec![],
            status: AgentStatus::PendingApproval,
        };
        let ceo = org::bootstrap_ceo(pool, &ceo, by).await.unwrap().id;
        let applied = org::apply_engineering(pool, company, by, &self.now())
            .await
            .unwrap();
        for hire in applied.hires {
            gov::decide_approval(pool, hire, true, ADMIN, None, &self.now())
                .await
                .unwrap();
        }
        let named = |name: &str| {
            applied
                .agents
                .iter()
                .find(|a| a.name == name)
                .unwrap_or_else(|| panic!("no {name}"))
                .id
        };
        Org {
            company,
            team: applied.team.id,
            ceo,
            cto: named("CTO"),
            po: named("Product Owner"),
            lead: named("Team Lead"),
            dev: named("Developer 1"),
            qa: named("QA"),
        }
    }

    /// A project of the org's team; the product owner commits its sprints alone.
    pub async fn project(&self, o: &Org, key: &str, mode: ProjectMode) -> ProjectId {
        let p = NewProject {
            company_id: o.company,
            team_id: Some(o.team),
            name: format!("{key} project"),
            key: key.to_owned(),
            mode,
            sprint_approval: SprintApproval::ProductOwner,
        };
        work::create_project(&self.pool, &p).await.unwrap().id
    }

    /// A task waiting on the admin, in `sprint` when given (a planned one).
    pub async fn issue(
        &self,
        project: ProjectId,
        title: &str,
        sprint: Option<SprintId>,
    ) -> IssueId {
        let i = NewIssue {
            project_id: project,
            epic_id: None,
            parent_id: None,
            kind: IssueKind::Task,
            title: title.to_owned(),
            body: String::new(),
            state: IssueState::Todo,
            owner: None,
            next_actor: Some(NextActor::Human(ADMIN)),
            points: Some(3),
            sprint_id: sprint,
        };
        work::create_issue(&self.pool, &i).await.unwrap().id
    }

    pub async fn key(&self, issue: IssueId) -> String {
        work::issue_key(&self.pool, issue).await.unwrap().unwrap()
    }

    /// Writes the script of the next run on `issue`: one MCP tool call per `(tool, args)`.
    /// Returns the run's number on the issue.
    pub async fn play(&mut self, issue: IssueId, calls: &[(&str, Value)]) -> u32 {
        let key = self.key(issue).await;
        self.play_key(&key, calls)
    }

    /// `play` for the issue with key `key`, which may not exist yet.
    pub fn play_key(&mut self, key: &str, calls: &[(&str, Value)]) -> u32 {
        let lines: Vec<Value> = calls
            .iter()
            .map(|(name, args)| {
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": args}})
            })
            .collect();
        self.play_requests(key, &lines)
    }

    /// The script of the next run on the issue with key `key`: these JSON-RPC requests, sent
    /// in order. Returns the run's number on the issue.
    pub fn play_requests(&mut self, key: &str, requests: &[Value]) -> u32 {
        let key = key.to_owned();
        let n = self.runs.entry(key.clone()).or_default();
        *n += 1;
        let lines: Vec<String> = requests.iter().map(Value::to_string).collect();
        let path = self.dir.join("plays").join(format!("{key}.{n}"));
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
        *n
    }

    /// The raw JSON-RPC replies of run `n` on the issue with key `key`, one per request.
    pub fn raw_replies(&self, key: &str, n: u32) -> Vec<Value> {
        self.file(&format!("{key}.{n}.out"))
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
            .collect()
    }

    /// A shell step for run `n` on the issue with key `key`, which may not exist yet.
    pub fn script_key(&self, key: &str, n: u32, sh: &str) {
        std::fs::write(self.dir.join("plays").join(format!("{key}.{n}.sh")), sh).unwrap();
    }

    /// What run `n`'s shell step on `key` printed.
    pub fn script_out(&self, key: &str, n: u32) -> String {
        self.file(&format!("{key}.{n}.sh.out"))
    }

    /// A shell step for run `n` on `issue`, run in its working dir before its tool calls.
    pub async fn script(&self, issue: IssueId, n: u32, sh: &str) {
        let key = self.key(issue).await;
        std::fs::write(self.dir.join("plays").join(format!("{key}.{n}.sh")), sh).unwrap();
    }

    /// A bare repo `origin.git` with one commit on `main`, for a project's `--repo`.
    pub fn origin(&self) -> PathBuf {
        let seed = self.dir.join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        git(&seed, &["init", "-q", "-b", "main"]);
        std::fs::write(seed.join("README.md"), "hello\n").unwrap();
        git(&seed, &["add", "."]);
        git(&seed, &["commit", "-qm", "init"]);
        git(&self.dir, &["clone", "-q", "--bare", "seed", "origin.git"]);
        self.dir.join("origin.git")
    }

    /// A bare repo `<name>.git` with one commit on `main`.
    pub fn bare(&self, name: &str) -> PathBuf {
        let seed = self.dir.join(format!("seed-{name}"));
        std::fs::create_dir_all(&seed).unwrap();
        git(&seed, &["init", "-q", "-b", "main"]);
        std::fs::write(seed.join("README.md"), format!("{name}\n")).unwrap();
        git(&seed, &["add", "."]);
        git(&seed, &["commit", "-qm", "init"]);
        let bare = format!("{name}.git");
        let from = format!("seed-{name}");
        git(&self.dir, &["clone", "-q", "--bare", &from, &bare]);
        self.dir.join(bare)
    }

    /// Gives `project` a repo (a fresh `origin.git`) on a forge of `kind` at `api` as
    /// `acme/app`, with `token` in a token file; the origin's path.
    pub async fn on_forge(
        &self,
        project: ProjectId,
        kind: Kind,
        api: &str,
        token: &str,
    ) -> PathBuf {
        let origin = self.origin();
        let repo = ProjectRepo {
            project_id: project,
            url: origin.display().to_string(),
            default_branch: "main".to_owned(),
        };
        work::set_project_repo(&self.pool, &repo).await.unwrap();
        let token_file = self.dir.join("forge-token");
        std::fs::write(&token_file, format!("{token}\n")).unwrap();
        let f = forge::ProjectForge {
            project_id: project,
            kind,
            api_url: api.to_owned(),
            repo: "acme/app".to_owned(),
            token_file,
        };
        let by = AuditActor::User(ADMIN);
        assert!(forge::set_project_forge(&self.pool, &f, by).await.unwrap());
        origin
    }

    /// One pass of the forge poller.
    pub async fn poll(&self) {
        citadel_server::forge::sync(&self.pool, &ainkrad_providers::client())
            .await
            .unwrap();
    }

    /// Hands `issue` to `agent` as the admin, which wakes it.
    pub async fn assign(&self, issue: IssueId, agent: AgentId) {
        let to = IssueTransition::Reassign {
            next: NextActor::Agent(agent),
        };
        work::transition_issue(&self.pool, issue, &to, AuditActor::User(ADMIN))
            .await
            .unwrap();
    }

    /// Wakes `agent` on `issue` by hand (a `manual` wake), as the admin would.
    pub async fn wake(&self, issue: IssueId, agent: AgentId) {
        let n = self.runs_on(issue).await;
        let w = citadel_core::exec::NewWakeRequest {
            agent_id: agent,
            issue_id: Some(issue),
            source: citadel_core::exec::WakeSource::Manual,
            reason: "test".to_owned(),
            idempotency_key: format!("test:{}:{}:{n}", issue.0, agent.0),
            not_before: None,
        };
        exec::enqueue_wake(&self.pool, &w).await.unwrap();
    }

    /// Waits until `runs` runs of `issue` have ended, and returns the last one's state.
    pub async fn ended(&self, issue: IssueId, runs: i64) -> String {
        self.ended_within(issue, runs, 60).await
    }

    /// `ended`, waiting up to `secs`.
    pub async fn ended_within(&self, issue: IssueId, runs: i64, secs: u64) -> String {
        for _ in 0..secs * 10 {
            let done: Vec<String> = sqlx::query_scalar(
                "SELECT state FROM runs WHERE issue_id = ? \
                 AND state NOT IN ('queued', 'claimed', 'running') ORDER BY id",
            )
            .bind(issue.0)
            .fetch_all(&self.pool)
            .await
            .unwrap();
            if done.len() as i64 >= runs {
                return done[runs as usize - 1].clone();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("issue {} never had {runs} ended runs", issue.0);
    }

    /// How many runs of `issue` there have been so far.
    pub async fn runs_on(&self, issue: IssueId) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM runs WHERE issue_id = ?")
            .bind(issue.0)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// The tool results of run `n` on `issue`, each parsed from its text (`{"error": text}`
    /// for a refused call).
    pub async fn replies(&self, issue: IssueId, n: u32) -> Vec<Value> {
        let key = self.key(issue).await;
        let out = self.file(&format!("{key}.{n}.out"));
        out.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let v: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"));
                let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
                if v["result"]["isError"] == true || v.get("error").is_some() {
                    json!({"error": if text.is_empty() { v.to_string() } else { text.to_owned() }})
                } else {
                    serde_json::from_str(text).unwrap_or(Value::Null)
                }
            })
            .collect()
    }

    /// The instructions run `n` on `issue` was given (empty when none).
    pub async fn instructions(&self, issue: IssueId, n: u32) -> String {
        let key = self.key(issue).await;
        self.file(&format!("{key}.{n}.instructions"))
    }

    fn file(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join("plays").join(name)).unwrap_or_default()
    }
}

/// Runs `git args…` in `dir` with a clean config.
pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@citadel.invalid",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}
