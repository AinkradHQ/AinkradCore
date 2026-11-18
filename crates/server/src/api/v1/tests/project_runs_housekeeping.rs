//! L1 (PR 318 review): the housekeeping path sends `run.stop` and `run.status` only. It is typed
//! (`RunHousekeeping`), so nothing else can reach a runner through it; here it is exercised
//! against a runner that is not connected.

use ainkrad_proto::v2::{ErrorCode, RunStatusReq, RunStop};

use super::*;
use crate::hub::RunHousekeeping;

#[tokio::test]
async fn housekeeping_sends_stop_and_status_and_answers_offline_for_an_unknown_runner() {
    let fx = fx().await;
    for op in [
        RunHousekeeping::Stop(RunStop { run: "r_x".into() }),
        RunHousekeeping::Status(RunStatusReq { run: None }),
    ] {
        let e = fx
            .app
            .hub
            .dispatch_run_housekeeping("nobody", op)
            .err()
            .expect("no such runner");
        assert_eq!(e.code, ErrorCode::Offline);
    }
}
