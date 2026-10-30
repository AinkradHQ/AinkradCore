//! Agent sessions end to end (E2-08, E2-07.2/.3): the real Core (service, store, hub, the
//! secrets broker over HTTP) and the real runner daemon with its agent driver, a scripted
//! harness standing in for Claude. Two sessions at once on one runner; a leased secret reaches
//! the harness and is masked everywhere the Core keeps text; a lease is good for its runner
//! only; the Core restarting and the runner restarting mid-session both leave a transcript with
//! no gap, and the runner restart resumes the harness.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key as SettingKey, Scope};
use ainkrad_core_server::agents::{self as service, AgentsConfig};
use ainkrad_core_server::gateway::Listen;
use ainkrad_core_server::store::agents::{self as sessions, NewSession, SessionSecret};
use ainkrad_core_server::store::secrets::{self as broker, NewValue};
use ainkrad_proto::runner::{Outcome, RunToken};
use ainkrad_runner::v2::agent::{AgentConfig, AgentDriver, secrets::http_redeem};
use ainkrad_runner::v2::client::Client;
use ainkrad_runner::v2::daemon::{Backoff, Daemon};
use ainkrad_runner::v2::key::{Enrolment, Key, State};
use ainkrad_runner::{Executor, Job, Report};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, watch};

use super::runner::{driver, paired, state};
use super::{Core, quick as hub_quick};

pub fn quick() -> AgentsConfig {
    AgentsConfig {
        read_wait: Duration::from_millis(500),
        retry: Duration::from_millis(100),
        lost_after: Duration::from_secs(60),
        answer: Duration::from_secs(5),
    }
}

const VALUE: &str = "throwaway-agent-token-5e1d";

type RunEnv = std::collections::HashMap<i64, Vec<(String, String)>>;

/// `sh -c <script>` with the run's own variables; each stdout line a `line` event.
#[derive(Clone, Default)]
struct Script {
    script: String,
    env: Arc<Mutex<RunEnv>>,
    /// The `RunToken` each run was handed.
    tokens: Arc<Mutex<Vec<String>>>,
}

fn script(s: &str) -> Script {
    Script {
        script: s.to_owned(),
        ..Script::default()
    }
}

impl Executor for Script {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        Ok(Some(format!("h-{}", job.context_ref)))
    }

    async fn run(&self, job: &Job, token: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        self.tokens.lock().unwrap().push(token.expose().to_owned());
        let env = self
            .env
            .lock()
            .unwrap()
            .get(&job.run)
            .cloned()
            .unwrap_or_default();
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&self.script)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .envs(env)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line == "APPROVAL" {
                let (reply, answer) = ainkrad_runner::Reply::new();
                let ask = Report::Approval {
                    id: "t1".to_owned(),
                    tool: "Bash".to_owned(),
                    input: json!({"command": "make deploy"}),
                    timeout_secs: 30,
                    reply,
                };
                let _ = reports.send(ask).await;
                let approved = answer.await.is_ok_and(|a| a.approved);
                let answered = json!({"type": "answer", "approved": approved});
                let _ = reports.send(Report::Event(answered)).await;
                continue;
            }
            let _ = reports
                .send(Report::Event(json!({"type": "line", "text": line})))
                .await;
        }
        let _ = child.wait().await;
        Outcome::Succeeded
    }

    fn session_env(&self, run: i64, env: Option<Vec<(String, String)>>) {
        let mut all = self.env.lock().unwrap();
        match env {
            Some(e) => drop(all.insert(run, e)),
            None => drop(all.remove(&run)),
        }
    }
}

/// A runner daemon serving `base` with an agent driver over `dir`, until `stop`.
struct Runner {
    id: String,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Runner {
    async fn halt(self) {
        self.stop.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

fn agent_config(dir: &Path) -> AgentConfig {
    AgentConfig {
        capacity: 2,
        ..AgentConfig::new(dir.join("agents"), dir.join("secrets"))
    }
}

async fn run_runner(core: &Core, base: &str, st: &State, exec: Script) -> Runner {
    let key = Arc::new(Key::load(&st.key()).unwrap());
    let enrolment = Arc::new(Mutex::new(Enrolment::load(&st.enrolment()).unwrap()));
    let id = enrolment.lock().unwrap().device_id.clone();
    let redeem = http_redeem(
        Arc::new(Client::new(base, None).unwrap()),
        Arc::clone(&key),
        Arc::clone(&enrolment),
    );
    let agents = AgentDriver::new(agent_config(&st.0), exec)
        .unwrap()
        .with_redeem(redeem);
    let daemon = Daemon {
        client: Client::new(base, None).unwrap(),
        key,
        enrolment,
        save: None,
        exec: driver(),
        pty: None,
        agents: Some(Arc::new(agents)),
        tls: None,
        backoff: Backoff {
            min: Duration::from_millis(50),
            max: Duration::from_millis(200),
            refused: Duration::from_millis(200),
        },
    };
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(async move {
        let _ = daemon.run(stopped).await;
    });
    until("the runner online", || core.app.hub.online(&id)).await;
    Runner { id, stop, task }
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn state_of(core: &Core, id: &str) -> sessions::Session {
    sessions::get(&core.app.pool, id).await.unwrap().unwrap()
}

/// Waits for the session to be over, then returns its transcript.
async fn finished(core: &Core, id: &str) -> (sessions::Session, Vec<Value>) {
    for _ in 0..500 {
        let s = state_of(core, id).await;
        if !s.live() {
            let t = sessions::transcript(&core.app.pool, id, 0, 10_000)
                .await
                .unwrap();
            let seqs: Vec<u64> = t.iter().map(|e| e.seq).collect();
            let want: Vec<u64> = (1..=u64::try_from(s.last_seq).unwrap()).collect();
            assert_eq!(seqs, want, "the stored transcript has every seq once");
            return (s, t.into_iter().map(|e| e.body).collect());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("session {id} did not end: {:?}", state_of(core, id).await);
}

pub(super) async fn throwaway_mode(core: &Core) {
    let now = core.app.clock.now();
    ainkrad_core_server::store::settings::set(
        &core.app.pool,
        SettingKey::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
}

pub(super) async fn secret(core: &Core, name: &str, runners: &[String], delivery: &str) {
    let sealer = core.app.secrets.as_deref().unwrap();
    let new = NewValue {
        value: VALUE,
        runners: Some(runners),
        delivery: Some(delivery),
    };
    let now = core.app.clock.now();
    broker::create(
        &core.app.pool,
        sealer,
        name,
        &new,
        &runners[0],
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
}

async fn session(core: &Core, runner: &str, secrets: &[SessionSecret]) -> String {
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner,
        harness: "fake",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets,
        created_by: runner,
    };
    let s = sessions::create(
        &core.app.pool,
        &new,
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    service::start(&core.app, &s)
        .await
        .unwrap_or_else(|e| panic!("{}", service::describe(&e)));
    s.id
}

/// Every text the Core keeps about sessions and secrets: transcripts, session rows, events,
/// audit rows, and its log.
async fn everything(core: &Core) -> String {
    let q = |sql: &'static str| sqlx::query_scalar::<_, String>(sql).fetch_all(&core.app.pool);
    let parts = [
        q("SELECT body FROM core_agent_transcript").await.unwrap(),
        q("SELECT json_array(id, coalesce(prompt, ''), secrets, coalesce(outcome, '')) FROM core_agent_sessions")
            .await
            .unwrap(),
        q("SELECT payload FROM events").await.unwrap(),
        q("SELECT details FROM audit_events").await.unwrap(),
    ];
    let log = String::from_utf8_lossy(&super::log().0.lock().unwrap()).into_owned();
    parts.concat().join("\n") + &log
}

#[tokio::test]
async fn two_sessions_run_at_once_and_a_secret_never_reaches_the_cores_records() {
    let core = Core::start("agents", hub_quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("agents");
    let e = paired(&core, &base, None, &st).await;
    throwaway_mode(&core).await;
    secret(
        &core,
        "test.token",
        std::slice::from_ref(&e.device_id),
        "env",
    )
    .await;
    let gate = st.0.join("go");
    let exec = script(&format!(
        "echo \"token=$TOKEN\"; while [ ! -e '{}' ]; do sleep 0.05; done; echo done",
        gate.display()
    ));
    let r = run_runner(&core, &base, &st, exec).await;
    let secrets = [SessionSecret {
        name: "test.token".to_owned(),
        var: "TOKEN".to_owned(),
    }];
    let a = session(&core, &r.id, &secrets).await;
    let b = session(&core, &r.id, &[]).await;
    // Both run at once, and the runner's capacity (2) is full.
    for id in [&a, &b] {
        assert_eq!(state_of(&core, id).await.state, "running");
    }
    let full = service::admit(&core.app, &r.id, "fake").await.unwrap_err();
    assert!(
        service::describe(&full).contains("capacity"),
        "{}",
        service::describe(&full)
    );
    let live = core.app.hub.runners();
    let agent = live[&r.id]
        .drivers
        .iter()
        .find(|d| d.name == "agent")
        .unwrap();
    assert_eq!((agent.capacity, agent.streams), (2, Some(12)));
    until("both transcripts flowing", || true).await;
    for _ in 0..200 {
        let t = sessions::transcript(&core.app.pool, &a, 0, 100)
            .await
            .unwrap();
        if t.iter().any(|e| e.body["type"] == "line") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    std::fs::write(&gate, "").unwrap();
    let (sa, ta) = finished(&core, &a).await;
    let (sb, _) = finished(&core, &b).await;
    assert_eq!((sa.state.as_str(), sb.state.as_str()), ("ended", "ended"));
    assert_eq!(sa.outcome.as_ref().unwrap()["kind"], "succeeded");
    assert_eq!(
        sa.harness_session.as_deref(),
        Some(format!("h-{a}").as_str())
    );
    let line = ta.iter().find(|b| b["type"] == "line").unwrap();
    assert_eq!(
        line["text"], "token=[redacted:test.token]",
        "delivered, and masked"
    );
    // The value is nowhere the Core keeps text; no lease is either (only its hash prefix in
    // the `secret.leased` audit row).
    let all = everything(&core).await;
    assert!(
        !all.contains(VALUE),
        "the value leaked into the Core's records"
    );
    assert!(
        !all.contains("\"l_"),
        "a lease id leaked into the Core's records"
    );
    let leased: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'secret.redeemed' \
         AND json_extract(details, '$.runner') = ?",
    )
    .bind(&r.id)
    .fetch_one(&core.app.pool)
    .await
    .unwrap();
    assert_eq!(leased, 1, "the runner redeemed its one lease itself");
    // The session's delivered secrets went with it.
    assert_eq!(std::fs::read_dir(st.0.join("secrets")).unwrap().count(), 0);
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
}

#[tokio::test]
async fn a_lease_is_redeemed_once_and_only_by_its_own_runner() {
    let core = Core::start("agents-lease", hub_quick()).await;
    let base = format!("http://{}", core.host);
    let (sa, sb) = (state("lease-a"), state("lease-b"));
    let a = paired(&core, &base, None, &sa).await;
    let b = paired(&core, &base, None, &sb).await;
    throwaway_mode(&core).await;
    secret(
        &core,
        "test.token",
        &[a.device_id.clone(), b.device_id.clone()],
        "file",
    )
    .await;
    let redeemer = |st: &State| {
        let key = Arc::new(Key::load(&st.key()).unwrap());
        let e = Arc::new(Mutex::new(Enrolment::load(&st.enrolment()).unwrap()));
        http_redeem(Arc::new(Client::new(&base, None).unwrap()), key, e)
    };
    let now = core.app.clock.now();
    let (lease, _) = broker::lease(
        &core.app.pool,
        "test.token",
        &a.device_id,
        None,
        &a.device_id,
        AuditActor::System,
        &now,
        core.app.clock.unix(),
    )
    .await
    .unwrap();
    // Another runner, in the secret's scope too, cannot redeem A's lease.
    let refused = redeemer(&sb)(lease.clone()).await.err().unwrap();
    assert!(refused.contains("404"), "{refused}");
    // A redeems it, once.
    let got = redeemer(&sa)(lease.clone()).await.ok().unwrap();
    assert_eq!((got.value.as_str(), got.delivery.as_str()), (VALUE, "file"));
    let again = redeemer(&sa)(lease).await.err().unwrap();
    assert!(again.contains("410"), "{again}");
    for st in [sa, sb] {
        let _ = std::fs::remove_dir_all(&st.0);
    }
}

/// Binds `port` again once the stopped Core let it go.
async fn free(port: u16) {
    for _ in 0..200 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("port {port} stayed taken");
}

/// The exit gate's middle steps (§4.2–3) for agents: the Core restarts mid-session (same
/// database and identity), the session goes on and its transcript has no gap; then the runner
/// restarts, the session comes back `interrupted` and is resumed on the harness's own session.
#[tokio::test]
async fn the_core_and_the_runner_restarting_mid_session_leave_no_gap_and_resume() {
    let dir = std::env::temp_dir().join(format!("core-hub-agents-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let listen = |port: u16| Listen::Tcp(format!("127.0.0.1:{port}"));
    let first = Core::start_on("restart", hub_quick(), listen(0), Some(&dir), None).await;
    let port = first.port;
    let base = format!("http://{}", first.host);
    let st = state("agents-restart");
    paired(&first, &base, None, &st).await;
    let (gate_a, gate_b) = (st.0.join("go-a"), st.0.join("go-b"));
    let ticking = |gate: &PathBuf| {
        script(&format!(
            "i=0; while [ ! -e '{}' ]; do i=$((i+1)); echo tick-$i; sleep 0.05; done; echo done",
            gate.display()
        ))
    };
    let r = run_runner(&first, &base, &st, ticking(&gate_a)).await;
    let id = session(&first, &r.id, &[]).await;
    let ticks = |core: &Core| {
        let pool = core.app.pool.clone();
        let id = id.clone();
        async move {
            let t = sessions::transcript(&pool, &id, 0, 10_000).await.unwrap();
            t.iter().filter(|e| e.body["type"] == "line").count()
        }
    };
    while ticks(&first).await < 5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The Core goes (every client and the runner's connection with it) and comes back.
    first.app.closing.send_replace(true);
    free(port).await;
    let second = Core::start_on("restart", hub_quick(), listen(port), Some(&dir), None).await;
    assert_eq!(
        service::resume_all(&second.app).await.unwrap(),
        1,
        "the session is supervised again"
    );
    until("the runner back", || second.app.hub.online(&r.id)).await;
    let before = ticks(&second).await;
    while ticks(&second).await < before + 5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        state_of(&second, &id).await.state,
        "running",
        "the harness never stopped"
    );
    // Now the runner restarts: a new process over the same state; its harness went.
    r.halt().await;
    let r = run_runner(&second, &base, &st, ticking(&gate_b)).await;
    for _ in 0..300 {
        let s = state_of(&second, &id).await;
        if s.resumes >= 1 && s.state == "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    std::fs::write(&gate_b, "").unwrap();
    let (s, t) = finished(&second, &id).await;
    assert_eq!(s.resumes, 1);
    assert_eq!(s.outcome.as_ref().unwrap()["kind"], "succeeded");
    let kinds: Vec<&str> = t.iter().filter_map(|b| b["type"].as_str()).collect();
    let at = |k: &str| kinds.iter().position(|x| *x == k).unwrap();
    assert!(at("interrupted") < kinds.iter().rposition(|x| *x == "started").unwrap());
    assert!(
        t.iter()
            .any(|b| b["type"] == "started" && b["resumed"] == true)
    );
    let events: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind = 'agent.state'")
            .fetch_all(&second.app.pool)
            .await
            .unwrap();
    assert!(
        events.iter().any(|p| p.contains("interrupted")),
        "{events:?}"
    );
    r.halt().await;
    std::mem::forget(first); // its Drop would remove the directory the second one uses
    let _ = std::fs::remove_dir_all(&st.0);
}

/// E2-08.4 through the Core: the harness's tool call becomes an `agent.approval_requested`
/// event (pushed to `approve` devices by the platform classifier); a decision sent by the Core
/// reaches the waiting harness, which goes on.
#[tokio::test]
async fn a_decision_from_the_core_unblocks_the_waiting_harness() {
    use ainkrad_core_server::push::Classifier;
    let core = Core::start("agents-approve", hub_quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("agents-approve");
    paired(&core, &base, None, &st).await;
    let r = run_runner(&core, &base, &st, script("echo APPROVAL; echo after")).await;
    let id = session(&core, &r.id, &[]).await;
    let mut asked = None;
    for _ in 0..300 {
        let after = ainkrad_core_server::store::events::list_events(&core.app.pool, 0, 1000)
            .await
            .unwrap();
        asked = after
            .into_iter()
            .find(|e| e.kind == "agent.approval_requested");
        if asked.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let asked = asked.expect("the approval reached the event log");
    assert_eq!(
        (
            asked.payload.0["session"].as_str(),
            asked.payload.0["request"].as_str()
        ),
        (Some(id.as_str()), Some("t1"))
    );
    let push = ainkrad_core_server::push::Platform
        .notification(&asked)
        .expect("pushed");
    assert_eq!((push.kind, push.scope), ("approval_needed", "approve"));
    assert_eq!(push.data["approval_id"], "t1");
    let decide = ainkrad_proto::v2::Command::AgentDecide(ainkrad_proto::v2::AgentDecide {
        session: id.clone(),
        request: "t1".to_owned(),
        approved: true,
        reply: None,
    });
    service::ask(
        &core.app,
        &r.id,
        decide,
        Duration::from_secs(5),
        Some(ainkrad_core_server::hub::Elevated::for_tests()),
    )
    .await
    .unwrap();
    let (s, t) = finished(&core, &id).await;
    assert_eq!(s.outcome.as_ref().unwrap()["kind"], "succeeded");
    assert!(
        t.iter()
            .any(|b| b["type"] == "answer" && b["approved"] == true),
        "{t:?}"
    );
    assert!(t.iter().any(|b| b["type"] == "approval_decided"));
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
}

/// A module that mints one credential per launch, as Citadel's run token.
struct Minter;

const MINTED: &str = "cit_run_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

impl ainkrad_core_server::module::Module for Minter {
    fn id(&self) -> &'static str {
        "tmod"
    }

    fn routes(&self) -> axum::Router<ainkrad_core_server::api::App> {
        axum::Router::new()
    }

    fn credentials<'a>(
        &'a self,
        _: &'a ainkrad_core_server::api::App,
        s: &'a sessions::Session,
    ) -> ainkrad_core_server::module::BoxFut<
        'a,
        Result<Vec<ainkrad_core_server::module::Credential>, String>,
    > {
        Box::pin(async move {
            assert_eq!(s.owner_ref.as_deref(), Some("run:1"));
            Ok(vec![ainkrad_core_server::module::Credential {
                var: "CITADEL_RUN_TOKEN".to_owned(),
                value: ainkrad_core_server::module::Zeroizing::new(MINTED.to_owned()),
            }])
        })
    }
}

#[tokio::test]
async fn a_module_credential_reaches_the_runner_as_its_run_token_and_nowhere_else() {
    let core = Core::start("agents-cred", hub_quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("cred");
    let e = paired(&core, &base, None, &st).await;
    let exec = script("echo \"env=[$CITADEL_RUN_TOKEN]\"");
    let tokens = exec.tokens.clone();
    let r = run_runner(&core, &base, &st, exec).await;
    let mut app = core.app.clone();
    app.modules = Arc::from([Arc::new(Minter) as Arc<dyn ainkrad_core_server::module::Module>]);
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner: &e.device_id,
        harness: "fake",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &e.device_id,
    };
    let s = service::ModuleAgents::named("tmod")
        .create_ref(&app, &new, Some("run:1"))
        .await
        .unwrap_or_else(|e| panic!("{}", service::describe(&e)));
    let (done, transcript) = finished(&core, &s.id).await;
    assert_eq!(done.outcome.as_ref().unwrap()["kind"], "succeeded");
    assert_eq!(done.owner_ref.as_deref(), Some("run:1"));
    // The driver was handed it as the run's token (for the harness's MCP config) ...
    assert_eq!(*tokens.lock().unwrap(), [MINTED]);
    // ... and it is not in the harness's environment.
    let line = transcript.iter().find(|b| b["type"] == "line").unwrap();
    assert_eq!(line["text"], "env=[]");
    // Nowhere the Core keeps text, and no lease id either.
    let all = everything(&core).await;
    assert!(
        !all.contains(MINTED),
        "the credential leaked into the Core's records"
    );
    assert!(
        !all.contains("\"l_"),
        "a lease id leaked into the Core's records"
    );
    let redeemed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'secret.redeemed' \
         AND json_extract(details, '$.name') = 'citadel_run_token'",
    )
    .fetch_one(&core.app.pool)
    .await
    .unwrap();
    assert_eq!(redeemed, 1);
    // Nothing waits to be redeemed any more, and the table holds no secret.
    let sealed: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secrets")
        .fetch_one(&core.app.pool)
        .await
        .unwrap();
    assert_eq!(sealed, 0, "an ephemeral credential is never stored");
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
}
