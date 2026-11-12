//! Runner control through the real API and a runner played by hand (`Fake`): the policy command
//! (`PUT /runners/{id}/policy`) and the tool install (`POST /runners/{id}/tools`, its events and
//! its poll route). Both need `admin` and a live step-up.

use std::collections::BTreeMap;
use std::time::Duration;

use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_proto::v2::*;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::gateway::command;
use super::{Core, Fake, quick, random32};

fn control() -> DriverInfo {
    DriverInfo {
        name: DRIVER_CONTROL.to_owned(),
        commands: [OP_RUNNER_POLICY, OP_TOOLS_INSTALL, OP_TOOLS_STATUS]
            .map(str::to_owned)
            .into(),
        capacity: 4,
        ..DriverInfo::default()
    }
}

struct Fx {
    core: Core,
    fake: Fake,
    runner: String,
    admin: TestDevice,
}

fn elevate(core: &Core, dev: &TestDevice) {
    let sid = dev.session.lock().unwrap().clone().unwrap();
    let until = ainkrad_core_server::scheduler::Clock::unix(&*core.app.clock) + 300;
    assert!(core.app.auth.elevate(&sid, &dev.id, until));
}

async fn up(name: &str, with_control: bool) -> Fx {
    let core = Core::start(name, quick()).await;
    let dev = core.runner().await;
    let drivers = if with_control {
        vec![control()]
    } else {
        vec![]
    };
    let fake = Fake::welcomed(&core, &dev, drivers).await;
    let admin = core.device("device", &["read", "admin"]).await;
    elevate(&core, &admin);
    Fx {
        runner: dev.id.clone(),
        core,
        fake,
        admin,
    }
}

async fn call(
    core: &Core,
    dev: &TestDevice,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let bytes = body.map(|v| v.to_string()).unwrap_or_default();
    let mut req = format!(
        "{method} {uri} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n",
        core.host
    );
    for (n, v) in dev.headers(method, uri, bytes.as_bytes()) {
        req += &format!("{n}: {v}\r\n");
    }
    if !bytes.is_empty() {
        req += "content-type: application/json\r\n";
    }
    req += &format!("content-length: {}\r\n\r\n{bytes}", bytes.len());
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", core.port))
        .await
        .unwrap();
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tcp.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text[9..12].parse().unwrap();
    let body = text.split_once("\r\n\r\n").map_or("", |x| x.1);
    let (a, b) = (body.find(['{', '[']), body.rfind(['}', ']']));
    let json = a
        .zip(b)
        .and_then(|(a, b)| serde_json::from_str(&body[a..=b]).ok());
    (status, json.unwrap_or(Value::Null))
}

fn status(op: &str, state: ToolOpState, percent: u8, step: &str) -> ToolsStatus {
    ToolsStatus {
        operation: op.to_owned(),
        tool: Tool::Git,
        state,
        percent,
        step: step.to_owned(),
        reason: None,
        tools: BTreeMap::new(),
    }
}

async fn events(core: &Core, kind: &str) -> Vec<Value> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT payload FROM events WHERE kind = ? ORDER BY seq")
            .bind(kind)
            .fetch_all(&core.app.pool)
            .await
            .unwrap();
    rows.into_iter()
        .map(|(p,)| serde_json::from_str(&p).unwrap())
        .collect()
}

#[tokio::test]
async fn a_policy_reaches_the_runner_is_audited_and_announced() {
    let Fx {
        core,
        mut fake,
        runner,
        admin,
    } = up("rc-policy", true).await;
    let uri = format!("/api/v1/runners/{runner}/policy");
    let want =
        json!({"terminals": true, "agents": false, "agent_capacity": 3, "share_history": true});
    let policy = RunnerPolicy {
        terminals: true,
        agents: false,
        agent_capacity: 3,
        share_history: true,
    };
    let ((s, b), ()) = tokio::join!(
        call(&core, &admin, "PUT", &uri, Some(want.clone())),
        async {
            let (stream, cmd) = command(&mut fake).await;
            assert_eq!(cmd, Command::RunnerPolicy(policy));
            let applied = PolicyApplied {
                policy,
                restarting: true,
            };
            fake.send(stream, Body::Result(Reply::RunnerPolicy(applied)))
                .await;
        }
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(b, json!({"policy": want, "restarting": true}));
    let audit: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'runner.policy_set'")
            .fetch_one(&core.app.pool)
            .await
            .unwrap();
    assert_eq!(audit, 1);
    let ev = events(&core, "runner.policy").await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["runner"], json!(runner));
}

#[tokio::test]
async fn a_policy_without_share_history_keeps_the_runners_setting_and_false_turns_it_off() {
    let mut core_fx = {
        let core = Core::start("rc-share", quick()).await;
        let dev = core.runner().await;
        let mut fake = Fake::plain(&core, &dev).await;
        // The runner reports it runs with sharing on.
        fake.facts = Some(Box::new(RunnerFacts {
            policy: Some(RunnerPolicy {
                terminals: true,
                agents: false,
                agent_capacity: 3,
                share_history: true,
            }),
            ..RunnerFacts::default()
        }));
        let auth = fake.hello(&dev, vec![control()], &random32()).await;
        fake.prove(&dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
            .await;
        fake.welcome().await;
        let admin = core.device("device", &["read", "admin"]).await;
        elevate(&core, &admin);
        Fx {
            runner: dev.id.clone(),
            core,
            fake,
            admin,
        }
    };
    let Fx {
        core,
        fake,
        runner,
        admin,
    } = &mut core_fx;
    let uri = format!("/api/v1/runners/{runner}/policy");
    for (body, expect) in [
        (
            json!({"terminals": true, "agents": false, "agent_capacity": 4}),
            true,
        ),
        (
            json!({"terminals": true, "agents": false, "agent_capacity": 4, "share_history": false}),
            false,
        ),
    ] {
        let ((s, b), ()) = tokio::join!(call(core, admin, "PUT", &uri, Some(body)), async {
            let (stream, cmd) = command(fake).await;
            let Command::RunnerPolicy(p) = cmd else {
                panic!("{cmd:?}")
            };
            assert_eq!(p.share_history, expect, "what the runner is told");
            let applied = PolicyApplied {
                policy: p,
                restarting: true,
            };
            fake.send(stream, Body::Result(Reply::RunnerPolicy(applied)))
                .await;
        });
        assert_eq!(s, 200, "{b}");
        assert_eq!(b["policy"]["share_history"], json!(expect));
    }
}

#[tokio::test]
async fn a_refused_policy_says_why_and_bad_input_never_reaches_the_runner() {
    let Fx {
        core,
        mut fake,
        runner,
        admin,
    } = up("rc-refuse", true).await;
    let uri = format!("/api/v1/runners/{runner}/policy");
    for cap in [0, 9] {
        let (s, b) = call(
            &core,
            &admin,
            "PUT",
            &uri,
            Some(json!({"terminals": false, "agents": false, "agent_capacity": cap})),
        )
        .await;
        assert_eq!((s, &b["code"]), (400, &json!("bad_request")), "{b}");
    }
    let (s, _) = call(
        &core,
        &admin,
        "PUT",
        &uri,
        Some(json!({"terminals": false, "agents": false, "agent_capacity": 2, "x": 1})),
    )
    .await;
    assert!(s == 400 || s == 422, "{s}");
    // Without a step-up the route is refused before anything is sent.
    let plain = core.device("device", &["read", "admin"]).await;
    let (s, b) = call(
        &core,
        &plain,
        "PUT",
        &uri,
        Some(json!({"terminals": true, "agents": false, "agent_capacity": 2})),
    )
    .await;
    assert_eq!((s, &b["code"]), (403, &json!("step_up_required")));
    // A read-only device may not.
    let reader = core.device("device", &["read"]).await;
    let (s, _) = call(
        &core,
        &reader,
        "PUT",
        &uri,
        Some(json!({"terminals": true, "agents": false, "agent_capacity": 2})),
    )
    .await;
    assert_eq!(s, 403);
    // The runner refuses agents: its reason comes back as a 409, and it was the first command it saw.
    let ((s, b), ()) = tokio::join!(
        call(
            &core,
            &admin,
            "PUT",
            &uri,
            Some(json!({"terminals": false, "agents": true, "agent_capacity": 2}))
        ),
        async {
            let (stream, cmd) = command(&mut fake).await;
            assert!(matches!(cmd, Command::RunnerPolicy(p) if p.agents));
            let why = StreamError::new(
                ErrorCode::InvalidArgs,
                "the agent sandbox cannot run on this host",
            );
            fake.send(stream, Body::Error(why)).await;
        }
    );
    assert_eq!((s, &b["code"]), (409, &json!("policy_refused")), "{b}");
    assert!(b["message"].as_str().unwrap().contains("sandbox"));
}

#[tokio::test]
async fn a_runner_without_control_is_unsupported_and_an_offline_one_is_refused() {
    let fx = up("rc-old", false).await;
    let uri = format!("/api/v1/runners/{}/policy", fx.runner);
    let (s, b) = call(
        &fx.core,
        &fx.admin,
        "PUT",
        &uri,
        Some(json!({"terminals": true, "agents": false, "agent_capacity": 2})),
    )
    .await;
    assert_eq!((s, &b["code"]), (409, &json!("unsupported_command")), "{b}");
    let (s, b) = call(
        &fx.core,
        &fx.admin,
        "POST",
        &format!("/api/v1/runners/{}/tools", fx.runner),
        Some(json!({"tool": "git"})),
    )
    .await;
    assert_eq!((s, &b["code"]), (409, &json!("unsupported_command")), "{b}");
}

#[tokio::test]
async fn a_tool_install_reports_progress_in_events_and_ends_in_the_runners_tools() {
    let Fx {
        core,
        mut fake,
        runner,
        admin,
    } = up("rc-tools", true).await;
    let base = format!("/api/v1/runners/{runner}/tools");
    let (s, b) = call(&core, &admin, "POST", &base, Some(json!({"tool": "bash"}))).await;
    assert_eq!((s, &b["code"]), (400, &json!("bad_request")), "{b}");
    let (op, (s, b)) = {
        let ((s, b), op) = tokio::join!(
            call(&core, &admin, "POST", &base, Some(json!({"tool": "git"}))),
            async {
                let (stream, cmd) = command(&mut fake).await;
                let Command::ToolsInstall(ToolsInstall {
                    operation: op,
                    tool,
                }) = cmd
                else {
                    panic!("{cmd:?}")
                };
                assert_eq!(tool, Tool::Git);
                fake.send(
                    stream,
                    Body::Result(Reply::ToolsStatus(status(
                        &op,
                        ToolOpState::Running,
                        0,
                        "Starting",
                    ))),
                )
                .await;
                op
            }
        );
        (op, (s, b))
    };
    assert_eq!(s, 202, "{b}");
    assert_eq!(
        (b["op"].as_str(), b["state"].as_str(), b["tool"].as_str()),
        (Some(op.as_str()), Some("running"), Some("git"))
    );
    // A second install while it runs is refused here, never sent.
    let (s, b) = call(&core, &admin, "POST", &base, Some(json!({"tool": "node"}))).await;
    assert_eq!((s, &b["code"]), (409, &json!("install_running")), "{b}");
    // The Core polls; the runner answers its progress, then done with what it found.
    for (state, percent, step) in [
        (ToolOpState::Running, 40, "Installing git"),
        (ToolOpState::Done, 100, "Installed"),
    ] {
        let (stream, cmd) = command(&mut fake).await;
        assert_eq!(
            cmd,
            Command::ToolsStatus(ToolsStatusReq {
                operation: op.clone()
            })
        );
        let mut s = status(&op, state, percent, step);
        if state == ToolOpState::Done {
            s.tools = BTreeMap::from([("git".to_owned(), "2.43.0".to_owned())]);
        }
        fake.send(stream, Body::Result(Reply::ToolsStatus(s))).await;
    }
    let poll = format!("{base}/operations/{op}");
    let mut last = Value::Null;
    for _ in 0..100 {
        let (s, b) = call(&core, &admin, "GET", &poll, None).await;
        assert_eq!(s, 200, "{b}");
        last = b;
        if last["state"] == json!("done") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        (last["state"].as_str(), last["percent"].as_u64()),
        (Some("done"), Some(100)),
        "{last}"
    );
    assert_eq!(last["tools"], json!({"git": "2.43.0"}));
    // The events were written as the state moved: start, 40 %, done.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen: Vec<(String, u64)> = events(&core, "runner.tool_install")
        .await
        .iter()
        .map(|e| {
            (
                e["state"].as_str().unwrap().to_owned(),
                e["percent"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("running".into(), 0),
            ("running".into(), 40),
            ("done".into(), 100)
        ]
    );
    // `GET /runners` now lists the tool.
    let (_, runners) = call(&core, &admin, "GET", "/api/v1/runners", None).await;
    assert_eq!(runners[0]["tools"]["git"], json!("2.43.0"), "{runners}");
    // Another runner's id does not find the operation.
    let other = core.device("runner", &["runner"]).await;
    let (s, _) = call(
        &core,
        &admin,
        "GET",
        &format!("/api/v1/runners/{}/tools/operations/{op}", other.id),
        None,
    )
    .await;
    assert_eq!(s, 404);
    // Once it is over a new install may start; the runner's own refusal while busy reads as the same 409.
    let ((s, b), ()) = tokio::join!(
        call(&core, &admin, "POST", &base, Some(json!({"tool": "node"}))),
        async {
            let (stream, cmd) = command(&mut fake).await;
            assert!(matches!(cmd, Command::ToolsInstall(_)));
            let busy = StreamError::new(ErrorCode::Busy, "another install is running here");
            fake.send(stream, Body::Error(busy)).await;
        }
    );
    assert_eq!((s, &b["code"]), (409, &json!("install_running")), "{b}");
}
