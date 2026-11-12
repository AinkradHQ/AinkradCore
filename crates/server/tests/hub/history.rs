//! `history.read` (E5-3) through the hub with a runner played by hand: the one fixed op carries
//! only the harness, a cursor and a size; a runner that did not list `history-read` is never sent
//! it; the runner's answer comes back as it is.

use std::collections::BTreeMap;

use ainkrad_core_server::agents::history::{HistoryError, read_history};
use ainkrad_proto::v2::*;

use super::gateway::command;
use super::{Core, Fake, agents, quick, random32};

async fn up(name: &str, offered: bool) -> (Core, Fake, String) {
    let core = Core::start_agents(name, quick(), agents::quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::plain(&core, &dev).await;
    let mut commands: Vec<String> = AGENT_OPS.iter().map(|o| (*o).to_owned()).collect();
    if offered {
        commands.push(CAP_HISTORY_READ.to_owned());
    }
    let driver = DriverInfo {
        name: AGENT_DRIVER.to_owned(),
        commands,
        capacity: 4,
        streams: Some(32),
        ..DriverInfo::default()
    };
    let auth = fake.hello(&dev, vec![driver], &random32()).await;
    fake.prove(&dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
        .await;
    fake.welcome().await;
    (core, fake, dev.id)
}

fn ask() -> HistoryRead {
    HistoryRead {
        harness: "claude".to_owned(),
        cursor: BTreeMap::from([("s1".to_owned(), 4)]),
        max_bytes: 1000,
    }
}

#[tokio::test]
async fn a_runner_that_listed_history_read_is_asked_the_one_fixed_op_and_its_answer_returns() {
    let (core, mut fake, runner) = up("hist-ok", true).await;
    let app = core.app.clone();
    let r = runner.clone();
    let task = tokio::spawn(async move { read_history(&app, &r, ask()).await });
    let (stream, cmd) = command(&mut fake).await;
    let Command::HistoryRead(c) = cmd else {
        panic!("{cmd:?}")
    };
    assert_eq!(
        (c.harness.as_str(), c.cursor["s1"], c.max_bytes),
        ("claude", 4, 1000)
    );
    let answer = HistoryChunk {
        items: vec![],
        cursor: BTreeMap::from([("s1".to_owned(), 9)]),
        skipped: vec![HistorySkip {
            reason: "restricted_path".to_owned(),
            count: 1,
        }],
        more: false,
    };
    fake.send(stream, Body::Result(Reply::HistoryRead(answer.clone())))
        .await;
    assert_eq!(task.await.unwrap(), Ok(answer));
}

#[tokio::test]
async fn a_runner_that_did_not_switch_sharing_on_is_never_sent_the_op() {
    let (core, _fake, runner) = up("hist-off", false).await;
    let got = read_history(&core.app, &runner, ask()).await;
    assert_eq!(got, Err(HistoryError("not_offered")));
    let got = read_history(&core.app, "d_nobody", ask()).await;
    assert_eq!(got, Err(HistoryError("not_offered")));
}
