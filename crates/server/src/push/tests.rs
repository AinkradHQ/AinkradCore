//! The pusher with a recording notifier, and the APNs request it would send (never sent).

use std::sync::Mutex;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::gov::{ApprovalKind, DeviceKeyId, NewApproval};
use ainkrad_core::org::{AgentStatus, Harness, NewAgent, OrgRole};
use ainkrad_core::work::{
    IssueKind, IssueState, NewIssue, NewProject, NextActor, ProjectMode, SprintApproval, UserId,
};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};

use super::apns::ApnsNotifier;
use super::*;
use crate::store::gov::{issue_device_key, open_approval, revoke_device_key, set_push_token};
use crate::store::org::{create_agent, create_company};
use crate::store::work::{create_issue, create_project};
use crate::store::{audit, connect};

struct Clocked(Mutex<String>);

impl Clock for Clocked {
    fn now(&self) -> String {
        self.0.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<(DeviceKeyId, Notification)>>);

impl Notifier for Recorder {
    fn send<'a>(&'a self, to: &'a PushTarget, n: &'a Notification) -> Sent<'a> {
        self.0.lock().unwrap().push((to.device, n.clone()));
        Box::pin(async { Ok(()) })
    }
}

impl Recorder {
    fn take(&self) -> Vec<(DeviceKeyId, Notification)> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

fn audited(action: &str, kind: &str, id: i64) -> NewAuditEvent {
    NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: kind.to_owned(),
            id,
        }),
        company_id: None,
        run_id: None,
        details: "{}".to_owned(),
    }
}

#[tokio::test]
async fn pushes_approvals_blocks_escalations_and_stuck_issues_to_live_devices_once() {
    let dir = std::env::temp_dir().join(format!("citadel-push-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("citadel.db")).await.unwrap();
    let company = create_company(&pool, "A").await.unwrap().id;
    let new = NewAgent {
        company_id: company,
        name: "dev".to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let agent = create_agent(&pool, &new).await.unwrap().id;
    let p = NewProject {
        company_id: company,
        team_id: None,
        name: "P".to_owned(),
        key: "PPP".to_owned(),
        mode: ProjectMode::Kanban,
        sprint_approval: SprintApproval::Owner,
    };
    let project = create_project(&pool, &p).await.unwrap().id;
    let i = NewIssue {
        project_id: project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Work".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Agent(agent)),
        points: None,
        sprint_id: None,
    };
    let issue = create_issue(&pool, &i).await.unwrap().id;

    let by = AuditActor::User(UserId(1));
    let token = |n: u8| format!("{n:02x}").repeat(32);
    let mut devices = vec![];
    for (n, name) in ["mac", "phone", "old", "silent"].iter().enumerate() {
        let (d, _) = issue_device_key(&pool, name, by).await.unwrap();
        if *name != "silent" {
            set_push_token(&pool, d.id, Some((&token(n as u8), false)))
                .await
                .unwrap();
        }
        devices.push(d.id);
    }
    revoke_device_key(&pool, devices[2], by, "2026-10-22T10:00:00.000Z")
        .await
        .unwrap();

    let recorder = Arc::new(Recorder::default());
    // Rows get the database's own time, so the fake clock starts at the real one.
    let clock = Arc::new(Clocked(Mutex::new(crate::scheduler::SystemClock.now())));
    let pusher = Pusher {
        pool: pool.clone(),
        notifier: recorder.clone(),
        clock: clock.clone(),
        every: Duration::from_secs(1),
    };
    let mut stuck = None;
    assert_eq!(
        pusher.tick(&mut stuck).await.unwrap(),
        0,
        "history is not pushed"
    );

    let ask = NewApproval {
        company_id: company,
        kind: ApprovalKind::PrMerge,
        issue_id: Some(issue),
        sprint_id: None,
        agent_id: None,
        requested_by: agent,
        payload: "{}".to_owned(),
    };
    let a = open_approval(&pool, &ask, &clock.now()).await.unwrap();
    audit::append(&pool, &audited("issue.blocked", "issue", issue.0))
        .await
        .unwrap();
    audit::append(&pool, &audited("loop_breaker.tripped", "issue", issue.0))
        .await
        .unwrap();
    audit::append(&pool, &audited("issue.todo", "issue", issue.0))
        .await
        .unwrap();
    assert_eq!(pusher.tick(&mut stuck).await.unwrap(), 3);
    let sent = recorder.take();
    let to: HashSet<i64> = sent.iter().map(|(d, _)| d.0).collect();
    assert_eq!(
        to,
        HashSet::from([devices[0].0, devices[1].0]),
        "live, with a token"
    );
    let kinds: Vec<&str> = sent.iter().step_by(2).map(|(_, n)| n.kind).collect();
    assert_eq!(kinds, ["approval", "blocked", "escalation"]);
    assert_eq!(sent[0].1.data["approval_id"], a.id.0);
    assert_eq!(sent[0].1.body, "A pr merge waits on you");
    assert_eq!(pusher.tick(&mut stuck).await.unwrap(), 0, "each once");

    // Much later, the untouched issue is stuck: pushed once, and not again after a restart.
    *clock.0.lock().unwrap() = "2099-01-01T00:00:00.000Z".to_owned();
    assert!(pusher.tick(&mut stuck).await.unwrap() >= 1);
    let sent = recorder.take();
    assert!(sent.iter().all(|(_, n)| n.kind == "stuck"), "{sent:?}");
    assert_eq!(sent[0].1.data["issue_id"], issue.0);
    assert_eq!(pusher.tick(&mut stuck).await.unwrap(), 0);
    let mut restarted = None;
    assert_eq!(pusher.tick(&mut restarted).await.unwrap(), 0);

    pool.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A throwaway P-256 key as Apple's `.p8` file would hold it, and its public key.
fn p8() -> (String, Vec<u8>) {
    use base64::Engine;
    let rng = SystemRandom::new();
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der.as_ref(), &rng).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    );
    (pem, pair.public_key().as_ref().to_vec())
}

#[test]
fn the_apns_request_carries_a_valid_es256_token_and_goes_to_the_right_gateway() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (pem, public) = p8();
    let apns = ApnsNotifier::new(&pem, "KEY123", "TEAM456", "com.ainkrad.app").unwrap();
    assert!(ApnsNotifier::new("not a key", "k", "t", "b").is_err());

    let jwt = apns.jwt(1_000_000).unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header, json!({"alg": "ES256", "kid": "KEY123"}));
    assert_eq!(claims, json!({"iss": "TEAM456", "iat": 1_000_000}));
    let signed = format!("{}.{}", parts[0], parts[1]);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public)
        .verify(
            signed.as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .expect("a valid ES256 signature");
    assert_eq!(
        apns.jwt(1_000_000 + 49 * 60).unwrap(),
        jwt,
        "reused while fresh"
    );
    assert_ne!(
        apns.jwt(1_000_000 + 51 * 60).unwrap(),
        jwt,
        "renewed after 50 minutes"
    );

    let n = Notification {
        kind: "approval",
        title: "Approval needed".to_owned(),
        body: "A pr merge waits on you".to_owned(),
        data: json!({"approval_id": 3, "seq": 9}),
    };
    let mut to = PushTarget {
        device: DeviceKeyId(1),
        token: "ab".repeat(32),
        sandbox: false,
    };
    let req = apns.request(&to, &n, 2_000_000).unwrap();
    assert_eq!(req.method(), "POST");
    assert_eq!(
        req.url().as_str(),
        format!("https://api.push.apple.com/3/device/{}", to.token)
    );
    let h = req.headers();
    assert_eq!(h["apns-topic"], "com.ainkrad.app");
    assert_eq!(h["apns-push-type"], "alert");
    assert!(
        h["authorization"]
            .to_str()
            .unwrap()
            .starts_with("Bearer ey")
    );
    let body: Value = serde_json::from_slice(req.body().unwrap().as_bytes().unwrap()).unwrap();
    assert_eq!(body["aps"]["alert"]["title"], "Approval needed");
    assert_eq!(body["citadel"]["data"]["approval_id"], 3);
    to.sandbox = true;
    let req = apns.request(&to, &n, 2_000_000).unwrap();
    assert_eq!(req.url().host_str(), Some("api.sandbox.push.apple.com"));
}

/// An account near or at its limit (E15.2) is pushed, counted or harness-reported.
#[test]
fn account_warnings_and_limits_are_pushed() {
    use crate::store::events::{StoredEvent, What};
    let event = |action: &str, details: serde_json::Value| StoredEvent {
        seq: 9,
        at: "2026-10-22T10:00:00.000Z".to_owned(),
        what: What::Audit {
            audit_seq: 1,
            action: action.to_owned(),
            actor: AuditActor::System,
            entity: Some(("account".to_owned(), 4)),
            company_id: None,
            run_id: None,
            details,
        },
    };
    let counted = serde_json::json!({"unit": "tokens", "used": 800, "max": 1000});
    let n = notification(&event("account.warning", counted)).unwrap();
    assert_eq!(n.kind, "account");
    assert_eq!(n.title, "Account near its limit");
    assert_eq!(n.body, "Account 4: 800 of 1000 tokens");
    assert_eq!(n.data, serde_json::json!({"account_id": 4, "seq": 9}));
    let reported = serde_json::json!({"window": "five_hour", "percent": 85});
    let n = notification(&event("account.warning", reported)).unwrap();
    assert_eq!(n.body, "Account 4 at 85% of its five_hour window");
    let n = notification(&event("account.limited", serde_json::json!({}))).unwrap();
    assert_eq!(n.title, "Account at its limit");
    assert!(notification(&event("account.limit_set", serde_json::json!({}))).is_none());
    let n = notification(&event("account.unhealthy", serde_json::json!({"drops": 3}))).unwrap();
    assert_eq!(
        n.body,
        "Account 4: the provider dropped 3 turns; its runs fall back"
    );
}

/// An issue whose repairs gave up (E15.8) and a full runner disk (E15.9) reach the admin.
#[test]
fn repairs_given_up_and_full_disks_are_pushed() {
    use crate::store::events::{StoredEvent, What};
    let event = |action: &str, kind: &str| StoredEvent {
        seq: 3,
        at: "2026-10-22T10:00:00.000Z".to_owned(),
        what: What::Audit {
            audit_seq: 1,
            action: action.to_owned(),
            actor: AuditActor::System,
            entity: Some((kind.to_owned(), 7)),
            company_id: None,
            run_id: None,
            details: serde_json::json!({}),
        },
    };
    let n = notification(&event("repair.exhausted", "issue")).unwrap();
    assert_eq!(
        (n.kind, n.title.as_str()),
        ("escalation", "Issue needs you")
    );
    assert_eq!(n.data, serde_json::json!({"issue_id": 7, "seq": 3}));
    let n = notification(&event("runner.disk_full", "runner")).unwrap();
    assert_eq!((n.kind, n.title.as_str()), ("runner", "Runner disk full"));
    assert_eq!(n.data, serde_json::json!({"runner_id": 7, "seq": 3}));
    assert!(
        notification(&event("repair.todo_idle", "issue")).is_none(),
        "routine"
    );
}
