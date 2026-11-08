//! The descriptor: valid, one capability per operation, one host, and its token shape is the
//! redactor's.

use super::*;

#[test]
fn the_descriptor_is_valid_and_every_operation_has_one_capability() {
    use crate::connections::slack::DESCRIPTOR;
    assert_eq!(DESCRIPTOR.problem(), None);
    assert_eq!(DESCRIPTOR.read_only(), ["read_messages"]);
    assert_eq!(DESCRIPTOR.auth_methods[0].id, "oauth");
    assert!(!DESCRIPTOR.auth_methods[0].advanced);
    assert_eq!(DESCRIPTOR.auth_methods[1].id, "token");
    assert!(DESCRIPTOR.auth_methods[1].advanced);
    let op = |o| DESCRIPTOR.capability_of(o).map(|c| (c.name, c.write));
    for o in [
        "slack.list_channels",
        "slack.read_channel",
        "slack.read_thread",
        "slack.get_user",
    ] {
        assert_eq!(op(o), Some(("read_messages", false)), "{o}");
    }
    for o in ["slack.post_message", "slack.add_reaction"] {
        assert_eq!(op(o), Some(("post_messages", true)), "{o}");
    }
    assert_eq!(DESCRIPTOR.limits.len(), 1);
    assert_eq!(DESCRIPTOR.limits[0].key, "channels");
    for o in ["slack.list_channels", "slack.get_user"] {
        assert!(DESCRIPTOR.is_self_limited(o), "{o}");
    }
    for o in [
        "slack.read_channel",
        "slack.read_thread",
        "slack.post_message",
        "slack.add_reaction",
    ] {
        assert!(!DESCRIPTOR.is_self_limited(o), "{o} needs a resource");
    }
    assert!(DESCRIPTOR.allows_host("slack.com"));
    assert_eq!(DESCRIPTOR.hosts.len(), 1);
    for h in [
        "slack.com.evil.test",
        "evil-slack.com",
        "api.slack.com",
        "files.slack.com",
    ] {
        assert!(!DESCRIPTOR.allows_host(h), "{h}");
    }
    // The budget is in calls, but Slack counts requests: calls times the most requests a call
    // makes stays under 60% of the lowest tier this adapter touches.
    let worst = DESCRIPTOR.hourly_calls * crate::connections::slack::MAX_REQUESTS_PER_CALL;
    assert!(
        worst * 10 <= crate::connections::slack::LIST_REQUESTS_PER_HOUR * 6,
        "{worst}"
    );
    const { assert!(DESCRIPTOR.hourly_calls >= 100) };
    assert!(DESCRIPTOR.own_shape_refresh && !DESCRIPTOR.token_shapes.is_empty());
    assert_eq!(Slack::new(None).descriptor().kind, "slack");
    assert!(Registry::builtin().get("slack").is_some());
    assert_eq!(
        crate::connections::adapter::builtin_descriptor("slack").map(|d| d.kind),
        Some("slack")
    );
}

/// The descriptor's token shape is the redactor's own name for Slack bot tokens (and the
/// rotating one), and so is the `xoxe-` refresh token (which is never an access token).
#[test]
fn the_declared_token_shape_is_the_redactors_and_covers_the_refresh_token() {
    use crate::connections::slack::DESCRIPTOR;
    let red = ainkrad_proto::redact::Redactor::new();
    let body = "a1B2c3D4e5".repeat(3);
    for t in [
        format!("xoxb-{body}"),
        format!("xoxe.xoxb-{body}"),
        format!("xoxp-{body}"),
    ] {
        assert_eq!(
            red.text(&t),
            format!("[redacted:{}]", DESCRIPTOR.token_shapes[0]),
            "{t}"
        );
    }
    let refresh = format!("xoxe-1-{body}");
    assert_eq!(
        red.text(&refresh),
        format!("[redacted:{}]", DESCRIPTOR.token_shapes[0])
    );
    assert!(refresh.starts_with(DESCRIPTOR.refresh_prefixes[0]));
    let reg = Registry::builtin();
    for d in reg.descriptors() {
        let t = crate::connections::adapter::builtin_descriptor(d.kind).unwrap();
        assert_eq!(t.token_shapes, d.token_shapes, "{}", d.kind);
        assert_eq!(t.refresh_prefixes, d.refresh_prefixes, "{}", d.kind);
    }
}

/// The secret gate, with tokens shaped like real ones (every other fixture is shapeless on
/// purpose). A pasted bot token is admitted only with `secrets.connections` on; a rotating
/// token, whose access value holds a second Slack shape, is refused at `secrets.mode` 1 even then.
#[tokio::test]
async fn real_shaped_slack_tokens_meet_the_secret_gate() {
    use crate::connections::slack::{oauth_material, token_material};
    use crate::store::connections::{NewConnection, create};
    let f = fx(false).await;
    let body = "a1B2c3D4e5".repeat(3);
    let plain = token_material(&format!("xoxb-{body}")).unwrap();
    let rotating = oauth_material(
        &format!("xoxe.xoxb-{body}"),
        Some(&format!("xoxe-1-{body}")),
        Some(&at(43_200)),
    )
    .unwrap();
    let who = f.cx(NOW).who;
    let new = |name| NewConnection {
        kind: "slack",
        name,
        label: "A Slack workspace",
        auth_method: "token",
    };
    let refused = |r: Result<_, crate::store::secrets::Error>| match r {
        Err(crate::store::secrets::Error::Refused { code, .. }) => code,
        Err(_) => "db",
        Ok(_) => "admitted",
    };
    let set = |v: &'static str| {
        crate::store::settings::set(
            &f.pool,
            Key::SecretsConnections,
            Scope::Server,
            v,
            AuditActor::System,
            NOW,
        )
    };
    set("0").await.unwrap();
    let r = create(&f.pool, &f.sealer, &f.reg, &new("a"), &plain, who).await;
    assert_eq!(refused(r), "real_secret_refused");
    set("1").await.unwrap();
    let r = create(&f.pool, &f.sealer, &f.reg, &new("b"), &plain, who).await;
    assert_eq!(refused(r), "admitted");
    let r = create(&f.pool, &f.sealer, &f.reg, &new("c"), &rotating, who).await;
    assert_eq!(refused(r), "real_secret_refused");
    // A refresh token of its own shape is admitted beside a bot token (the kind says its refresh
    // tokens have a shape of their own), one of another service's shape never is.
    let own = crate::connections::material::Material::new(
        &format!("xoxb-{body}"),
        Some(&format!("xoxe-1-{body}")),
        None,
    )
    .unwrap();
    let r = create(&f.pool, &f.sealer, &f.reg, &new("d"), &own, who).await;
    assert_eq!(refused(r), "admitted");
    let foreign = crate::connections::material::Material::new(
        &format!("xoxb-{body}"),
        Some(&format!("ghp_{body}")),
        None,
    )
    .unwrap();
    let r = create(&f.pool, &f.sealer, &f.reg, &new("e"), &foreign, who).await;
    assert_eq!(refused(r), "real_secret_refused");
    // Slack's other prefixes are redacted but are never a credential, whatever the lift.
    for t in ["xapp-1-", "xoxa-2-", "xoxr-", "xoxs-"] {
        let m =
            crate::connections::material::Material::new(&format!("{t}{body}"), None, None).unwrap();
        let r = create(&f.pool, &f.sealer, &f.reg, &new("f"), &m, who).await;
        assert_eq!(refused(r), "real_secret_refused", "{t}");
    }
}
