//! The descriptor as data (its budget in the unit Linear counts), and the identity line.

use super::*;

#[test]
fn the_descriptor_is_valid_and_every_operation_has_one_capability() {
    use crate::connections::linear::DESCRIPTOR;
    assert_eq!(DESCRIPTOR.problem(), None);
    assert_eq!(DESCRIPTOR.read_only(), ["read_issues"]);
    assert_eq!(DESCRIPTOR.auth_methods[0].id, "oauth");
    assert!(!DESCRIPTOR.auth_methods[0].advanced);
    assert_eq!(DESCRIPTOR.auth_methods[1].id, "token");
    assert!(DESCRIPTOR.auth_methods[1].advanced);
    let op = |o| DESCRIPTOR.capability_of(o).map(|c| c.name);
    assert_eq!(op("linear.create_issue"), Some("write_issues"));
    assert_eq!(op("linear.update_issue"), Some("write_issues"));
    assert_eq!(op("linear.add_comment"), Some("write_issues"));
    assert_eq!(op("linear.search_issues"), Some("read_issues"));
    assert_eq!(DESCRIPTOR.limits.len(), 1);
    assert_eq!(DESCRIPTOR.limits[0].key, "teams");
    for o in [
        "linear.search_issues",
        "linear.list_teams",
        "linear.list_projects",
    ] {
        assert!(DESCRIPTOR.is_self_limited(o), "{o}");
    }
    for o in [
        "linear.get_issue",
        "linear.create_issue",
        "linear.update_issue",
    ] {
        assert!(!DESCRIPTOR.is_self_limited(o), "{o} needs a resource");
    }
    let bad = crate::connections::adapter::Descriptor {
        self_limited: &["linear.nope"],
        ..DESCRIPTOR
    };
    assert!(
        bad.problem().is_some(),
        "a self-limited name must be an operation"
    );
    assert!(DESCRIPTOR.allows_host("api.linear.app") && DESCRIPTOR.allows_host("linear.app"));
    assert_eq!(DESCRIPTOR.hosts.len(), 2);
    assert!(!DESCRIPTOR.allows_host("api.linear.app.evil.test"));
    assert!(!DESCRIPTOR.allows_host("evil-linear.app"));
    // The budget is in calls, but Linear counts requests: calls times the most requests a call
    // makes stays under 60% of Linear's key budget (the smaller of its two).
    let worst = DESCRIPTOR.hourly_calls * crate::connections::linear::MAX_REQUESTS_PER_CALL;
    assert!(
        worst * 10 <= crate::connections::linear::KEY_REQUESTS_PER_HOUR * 6,
        "{worst}"
    );
    const { assert!(DESCRIPTOR.hourly_calls >= 100) }; // and not absurdly small
    assert_eq!(Linear::new(None).descriptor().kind, "linear");
    let reg = Registry::builtin();
    assert!(reg.get("linear").is_some());
    assert_eq!(
        crate::connections::adapter::builtin_descriptor("linear").map(|d| d.kind),
        Some("linear")
    );
}

#[test]
fn the_identity_line_carries_the_organization_id_and_is_compared_by_it() {
    use crate::connections::linear::{OrgCheck, Viewer, check_org, identity_of, org_of};
    let me = Viewer {
        id: ME.to_owned(),
        workspace: ORG.to_owned(),
        org: ORG_ID.to_owned(),
    };
    let line = identity_of(&me);
    assert_eq!(line, identity());
    assert_eq!(org_of(&line), Some(ORG_ID));
    assert_eq!(check_org(Some(&line), ORG_ID), OrgCheck::Same);
    // A renamed workspace is still the same one; another id is another workspace.
    let renamed = line.replace(" acme ", " acme-inc ");
    assert_eq!(check_org(Some(&renamed), ORG_ID), OrgCheck::Same);
    assert_eq!(check_org(Some(&line), "someone-else"), OrgCheck::Different);
    // Nothing recorded, or a line with no id (an old format, a hand-written one): unknown.
    for old in [
        None,
        Some(""),
        Some("5f1c at acme"),
        Some("x (y z)"),
        Some("x ()"),
    ] {
        assert_eq!(check_org(old, ORG_ID), OrgCheck::Unknown, "{old:?}");
    }
}

#[test]
fn an_own_shape_refresh_token_needs_a_token_shape() {
    use crate::connections::linear::DESCRIPTOR;
    let bad = crate::connections::adapter::Descriptor {
        token_shapes: &[],
        ..DESCRIPTOR
    };
    assert!(bad.problem().is_some());
    assert!(DESCRIPTOR.own_shape_refresh && DESCRIPTOR.problem().is_none());
}
