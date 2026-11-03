//! KAN-417: a revoked device's open terminal socket closes with 4001 within the documented 5 s,
//! whether the revocation reached this process by the broadcast (the API) or only through the
//! store (the admin CLI, another process: the 2 s database backstop). Another device's socket on
//! its own terminal is untouched. Real Core API, runner daemon and `ainkrad-ptyhost`.

use super::*;

/// The close code of the socket's end, `None` for a socket that ended without a close frame.
async fn close_code(c: &mut Client2, secs: u64) -> Option<u16> {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(end, c.ws.next()).await {
            Err(_) => panic!("the socket stayed open for {secs} s after the revocation"),
            Ok(Some(Ok(Message::Close(frame)))) => return frame.map(|f| u16::from(f.code)),
            Ok(None | Some(Err(_))) => return None,
            Ok(_) => {}
        }
    }
}

async fn revoked_socket_closes(name: &str, broadcast: bool) {
    let fx = Fx::new(name).await;
    let gone = fx.device(true).await;
    let (mine, theirs) = (fx.sh(&gone).await, fx.sh(&fx.owner).await);
    let mut socket = fx.ws(&gone, &mine).await;
    socket.read_until("ready").await;
    let mut bystander = fx.ws(&fx.owner, &theirs).await;
    bystander.read_until("ready").await;

    let now = fx.core.app.clock.now();
    let done = gov::revoke_device(&fx.core.app.pool, &gone.id, AuditActor::System, None, &now);
    assert!(done.await.unwrap());
    if broadcast {
        fx.core.app.auth.revoked(&gone.id);
    }
    assert_eq!(close_code(&mut socket, 5).await, Some(4001));

    // Not a blanket close: the other device keeps its terminal and its socket.
    assert!(!bystander.ended(3).await, "the bystander's socket closed");
    bystander.type_line(TYPED).await;
    bystander.read_until(&format!("got:{TYPED}")).await;
    // The revoked device cannot come back with the same credentials.
    let (status, _) = fx
        .call(&gone, "GET", &format!("/api/v1/terminals/{mine}"), None)
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn revoking_through_the_api_closes_the_terminal_socket_with_4001() {
    revoked_socket_closes("t-rev-api", true).await;
}

#[tokio::test]
async fn a_revocation_the_broadcast_never_saw_closes_it_through_the_backstop() {
    revoked_socket_closes("t-rev-store", false).await;
}
