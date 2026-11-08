//! The descriptor: what the UI and the store read, the budget against Microsoft's limit, the scope
//! list, and the decision not to give Microsoft's tokens a redactor shape.

use ainkrad_proto::redact::Redactor;

use super::*;
use crate::connections::adapter::builtin_descriptor;
use crate::connections::teams::ops::plan;
use crate::connections::teams::{DESCRIPTOR, MAX_REQUESTS_PER_CALL};

#[test]
fn the_descriptor_is_valid_and_registers() {
    assert_eq!(DESCRIPTOR.problem(), None);
    let mut reg = Registry::new();
    reg.register(std::sync::Arc::new(Teams::new(None))).unwrap();
    assert!(builtin_descriptor("teams").is_some());
    assert!(Registry::builtin().get("teams").is_some());
    assert_eq!(
        DESCRIPTOR.hosts,
        ["graph.microsoft.com", "login.microsoftonline.com"]
    );
    assert_eq!(DESCRIPTOR.limits.len(), 1);
    assert_eq!(DESCRIPTOR.limits[0].key, "channels");
    let m: Vec<&str> = DESCRIPTOR.auth_methods.iter().map(|m| m.id).collect();
    assert_eq!(
        m,
        ["oauth"],
        "no token paste: an access token lasts an hour and cannot renew"
    );
    assert!(!DESCRIPTOR.auth_methods[0].advanced);
}

#[test]
fn capabilities_are_named_plainly_and_writes_are_separate() {
    let read = DESCRIPTOR.capability("read_messages").unwrap();
    let write = DESCRIPTOR.capability("post_messages").unwrap();
    assert!(!read.write && write.write);
    assert_eq!(
        write.operations,
        ["teams.post_message", "teams.reply_message"]
    );
    assert_eq!(DESCRIPTOR.read_only(), ["read_messages"]);
    // Every operation is one `plan` knows (it refuses its arguments, not its name).
    let ops = DESCRIPTOR.capabilities.iter().flat_map(|c| c.operations);
    for op in ops {
        let e = plan(
            op,
            &serde_json::json!({"nothing": 1}),
            &crate::connections::teams::Limit::any(),
        )
        .unwrap_err();
        assert!(!e.contains("no such operation"), "{op}: {e}");
    }
    for op in DESCRIPTOR.self_limited {
        assert!(DESCRIPTOR.capability_of(op).is_some());
    }
    assert_eq!(
        DESCRIPTOR.self_limited,
        ["teams.list_teams", "teams.list_channels"]
    );
}

#[test]
fn the_hourly_budget_is_at_most_sixty_percent_of_microsofts_channel_limit() {
    // 1 request a second on one channel: 3,600 an hour.
    let limit = 3_600u32;
    assert_eq!(
        MAX_REQUESTS_PER_CALL, 5,
        "the channel confirmation, the operation, a renewal's retry and /me after a refusal"
    );
    let worst = DESCRIPTOR.hourly_calls * MAX_REQUESTS_PER_CALL;
    assert!(worst <= limit * 6 / 10, "{worst}");
    assert!(worst * 2 > limit, "and not needlessly low: {worst}");
}

#[test]
fn the_scopes_are_the_least_that_do_the_job() {
    for want in [
        "openid",
        "offline_access",
        "User.Read",
        "ChannelMessage.Send",
        "ChannelMessage.Read.All",
    ] {
        assert!(SCOPES.split(' ').any(|s| s == want), "{want}");
    }
    for never in [
        "Chat",
        "Mail",
        "Files",
        "Calendar",
        "ReadWrite",
        "Delete",
        "Group",
        "Directory",
        "full_access",
        ".default",
    ] {
        assert!(!SCOPES.contains(never), "{never}");
    }
}

#[test]
fn microsofts_tokens_have_no_redactor_shape_by_decision() {
    // A JWT (`eyJ`) is every service's token; a shape for it would redact (and at the secret gate
    // refuse) any other JWT. The credential is kept base32 so no shape can misread it, and the
    // broker scrubs the raw tokens by value. This pins the decision: no shape, no refresh prefix.
    assert!(DESCRIPTOR.token_shapes.is_empty() && DESCRIPTOR.refresh_prefixes.is_empty());
    const { assert!(!DESCRIPTOR.own_shape_refresh) };
    let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ4In0.c2lnbmF0dXJlLWJ5dGVz";
    assert_eq!(Redactor::new().text(jwt), jwt);
}
