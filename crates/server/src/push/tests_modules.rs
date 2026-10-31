//! A module's pushes through the Core (`modules::Modules`): confined to its declared kinds and
//! scopes, ids only, only to the devices whose scopes allow them, and a typo in a declaration
//! stops the server.

use axum::Router;
use serde_json::json;

use super::modules::{Modules, validate};
use super::tests::Recorder;
use super::*;
use crate::api::App;
use crate::auth::testing::TestDevice;
use crate::module::Module;
use crate::store::connect;
use crate::store::gov::{get_device, set_push_token};

/// A module with declared kinds that tries, per audit action, what it must not be able to do.
struct Toy;

impl Module for Toy {
    fn id(&self) -> &'static str {
        "toy"
    }
    fn routes(&self) -> Router<App> {
        Router::new()
    }
    fn notification_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[("toy.alert", "read"), ("toy.big", "approve")]
    }
    fn classify(&self, e: &StoredEvent) -> Option<Notification> {
        let action = e.payload.0["action"].as_str()?.to_owned();
        // Anything it is handed becomes a push, to see what the Core lets through.
        let (kind, scope): (&'static str, &'static str) = match action.as_str() {
            "toy.alert" => ("toy.alert", "admin"),
            "toy.big" => ("toy.big", "read"),
            "toy.platform_kind" => ("approval_needed", "read"),
            "toy.foreign_kind" => ("other.alert", "read"),
            _ => ("toy.alert", "read"),
        };
        let data = json!({
            "id": 5, "token": "abcdefghijklmnop", "output": "$ cat ~/.ssh/id_ed25519",
            "nested": {"id": 1}, "path": "/etc/passwd",
        });
        Some(Notification {
            collapse: Some("approval_needed".to_owned()),
            ..Notification::new(kind, scope, &"T".repeat(500), &"b".repeat(900), data)
        })
    }
}

fn audited(action: &str) -> NewAuditEvent {
    NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: None,
        details: "{}".to_owned(),
    }
}

#[tokio::test]
async fn a_module_push_is_confined_to_its_kinds_scopes_and_devices() {
    let dir = std::env::temp_dir().join(format!("core-push-mod-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let actions = [
        "toy.alert",
        "toy.big",
        "toy.platform_kind",
        "toy.foreign_kind",
        "toy.other",
        "other.thing",
    ];
    crate::store::kinds::allow(&pool, &[], &actions).await;

    let mut seq = vec![];
    for (n, (name, scopes)) in [("phone", vec!["read"]), ("mac", vec!["read", "approve"])]
        .into_iter()
        .enumerate()
    {
        let clock = Arc::new(crate::scheduler::SystemClock);
        let d = TestDevice::enroll(&pool, name, "device", &scopes, "fp", clock).await;
        set_push_token(&pool, &d.id, Some((&format!("{n:02x}").repeat(32), false)))
            .await
            .unwrap();
        seq.push(get_device(&pool, &d.id).await.unwrap().unwrap().seq);
    }
    let (phone, mac) = (seq[0], seq[1]);

    let recorder = Arc::new(Recorder::default());
    let providers: Vec<Arc<dyn PushProvider>> = vec![recorder.clone()];
    let modules: Arc<[Arc<dyn Module>]> = Arc::from(vec![Arc::new(Toy) as Arc<dyn Module>]);
    let pusher = Pusher::new(
        pool.clone(),
        providers,
        Arc::new(Modules(modules)),
        Duration::from_secs(1),
        Arc::new(crate::scheduler::SystemClock),
    );
    pusher.tick().await.unwrap();
    for action in actions {
        audit::append_one(&pool, &audited(action)).await.unwrap();
    }
    pusher.tick().await.unwrap();
    let sent = recorder.take();
    let got = |device: i64| -> Vec<&Notification> {
        sent.iter()
            .filter(|(d, _)| d.0 == device)
            .map(|(_, n)| n)
            .collect()
    };

    // The `read` phone: toy.alert (and the module's `toy.other`, same declared kind) and
    // nothing at `approve`, even though the module asked for `toy.big` at `read`.
    let phone_kinds: Vec<&str> = got(phone).iter().map(|n| n.kind).collect();
    assert!(
        phone_kinds.iter().all(|k| *k == "toy.alert"),
        "{phone_kinds:?}"
    );
    assert!(!phone_kinds.is_empty());
    // The `approve` device also gets toy.big, at the declared scope.
    let mac_kinds: Vec<&str> = got(mac).iter().map(|n| n.kind).collect();
    assert!(mac_kinds.contains(&"toy.big") && mac_kinds.contains(&"toy.alert"));
    // Never a platform kind, another module's kind, or an event that is not the module's.
    for (_, n) in &sent {
        assert!(n.kind.starts_with("toy."), "{}", n.kind);
        assert!(
            n.scope == "read" || n.scope == "approve",
            "scope was fixed by the declaration"
        );
        assert!(n.title.chars().count() <= 80 && n.body.chars().count() <= 200);
        let keys: Vec<&String> = n.data.as_object().unwrap().keys().collect();
        assert!(
            keys.iter().all(|k| *k == "id" || *k == "count"),
            "ids only: {keys:?}"
        );
        assert_eq!(n.data["id"], 5);
    }
    assert_eq!(sent.len(), got(phone).len() + got(mac).len());
    // `toy.alert` and `toy.other` are one kind and one burst; `toy.platform_kind`,
    // `toy.foreign_kind` and `other.thing` pushed nothing.
    assert_eq!(got(phone).len(), 1);
    assert_eq!(got(mac).len(), 2);

    pool.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

type Kinds = &'static [(&'static str, &'static str)];

struct Declares {
    kinds: &'static [(&'static str, &'static str)],
    commands: &'static [&'static str],
}

impl Module for Declares {
    fn id(&self) -> &'static str {
        "toy"
    }
    fn routes(&self) -> Router<App> {
        Router::new()
    }
    fn notification_kinds(&self) -> &'static [(&'static str, &'static str)] {
        self.kinds
    }
    fn admin_commands(&self) -> &'static [&'static str] {
        self.commands
    }
}

#[test]
fn a_bad_declaration_stops_the_server_at_start() {
    let fine = Declares {
        kinds: &[("toy.a", "read"), ("toy.b.c", "admin")],
        commands: &["seed"],
    };
    validate(&fine);
    let long: &'static str = Box::leak(format!("toy.{}", "a".repeat(80)).into_boxed_str());
    let long: Kinds = Box::leak(Box::new([(long, "read")]));
    let bad: [(Kinds, &[&str]); 16] = [
        (&[("toy.a.", "read")], &[]),
        (&[("toy.a..b", "read")], &[]),
        (&[("toy..a", "read")], &[]),
        (&[("toy.a._b", "read")], &[]),
        (&[("toy.é", "read")], &[]),
        (&[("toy.A", "read")], &[]),
        (long, &[]),
        (&[("approval_needed", "read")], &[]),
        (&[("agent_finished", "agent")], &[]),
        (&[("other.alert", "read")], &[]),
        (&[("toy", "read")], &[]),
        (&[("toy.", "read")], &[]),
        (&[("toy.a", "runner")], &[]),
        (&[("toy.a", "root")], &[]),
        (&[("toy.a", "read"), ("toy.a", "admin")], &[]),
        (&[], &["Seed"]),
    ];
    for (kinds, commands) in bad {
        let m = Declares { kinds, commands };
        assert!(
            std::panic::catch_unwind(|| validate(&m)).is_err(),
            "{kinds:?} {commands:?} must be refused"
        );
    }
    let twice = Declares {
        kinds: &[],
        commands: &["seed", "seed"],
    };
    assert!(std::panic::catch_unwind(|| validate(&twice)).is_err());
}
