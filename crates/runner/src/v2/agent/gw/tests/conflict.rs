//! A gateway grant next to a provider-account secret (KAN-435 G6, spec 4.3).

use super::*;

#[tokio::test]
async fn a_gateway_grant_with_a_provider_account_secret_is_refused_before_anything_is_delivered() {
    let r = rig("gw-conflict", true);
    // Valid for the harness on its own (the variable is its own), so only the grant refuses it.
    let req = AgentStart {
        harness: "claude".to_owned(),
        secrets: vec![ainkrad_proto::v2::SecretGrant {
            lease: "l_fast".to_owned(),
            var: "ANTHROPIC_API_KEY".to_owned(),
        }],
        ..gateway_start("l_fast")
    };
    r.d.start(req).unwrap();
    until("the session to end", || {
        r.d.states().get(SESSION) == Some(&AgentState::Ended)
    })
    .await;
    assert_eq!(r.rec.started.load(Ordering::SeqCst), 0, "the harness ran");
    let ev =
        r.d.read(&AgentRead {
            session: SESSION.to_owned(),
            after: 0,
            wait_ms: None,
            gw_after: 0,
        })
        .await
        .unwrap();
    match ev.outcome {
        Some(Outcome::Failed { reason, .. }) => {
            assert!(reason.contains("provider-account secret"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    // Nothing was written for it, and no gateway was opened.
    let dir = r.d.config.secrets_dir.join(SESSION);
    assert!(
        !dir.exists() || std::fs::read_dir(&dir).unwrap().next().is_none(),
        "a secret file was written"
    );
    assert!(ceiling_of(&r.d).is_none());
    // The same secret without a gateway grant is today's account session, not refused by this rule.
    let granted = [(
        "acct.anthropic.1".to_owned(),
        "ANTHROPIC_API_KEY".to_owned(),
    )];
    assert_eq!(super::super::account_conflict(false, &granted), None);
    assert!(super::super::account_conflict(true, &granted).is_some());
}
