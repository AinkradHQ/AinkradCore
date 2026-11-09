use serde_json::json;

use super::*;

fn profile(v: serde_json::Value) -> Profile {
    serde_json::from_value(v).unwrap()
}

const POLICIES: Policies = Policies {
    sprint_approval: "owner",
    permission_mode: "ask",
};

#[test]
fn an_empty_profile_tells_a_run_nothing() {
    assert_eq!(Profile::default().sections(vec![], &POLICIES), vec![]);
    assert_eq!(fit(vec![], 4096), Fitted::default());
}

#[test]
fn bad_values_are_refused_with_the_reason() {
    for (bad, why) in [
        (json!({"definition_of_done": [" "]}), "empty entry"),
        (json!({"stack": "x".repeat(MAX_TEXT + 1)}), "longer than"),
        (
            json!({"environments": [{"name": "Prod"}, {"name": "prod"}]}),
            "twice",
        ),
        (
            json!({"environments": [{"name": "Prod", "url": "https://u:p@prod.example"}]}),
            "credentials",
        ),
        (
            json!({"environments": [{"name": "Prod", "url": "ftp://prod"}]}),
            "http(s)",
        ),
        (json!({"models": [{"role": "Dev", "model": ""}]}), "model"),
    ] {
        let got = profile(bad.clone()).problem();
        assert!(
            got.as_deref().is_some_and(|g| g.contains(why)),
            "{bad}: {got:?}"
        );
    }
    let good = json!({"environments": [{"name": "Staging", "url": "https://staging.example"}],
                      "models": [{"role": "Developer", "model": "sonnet", "small": "haiku"}]});
    assert_eq!(profile(good).problem(), None);
    assert!(serde_json::from_value::<Profile>(json!({"colour": "red"})).is_err());
}

#[test]
fn a_patch_changes_only_its_fields() {
    let mut p = profile(json!({"stack": "Rust", "docs": ["a.md"]}));
    let patch: ProfilePatch =
        serde_json::from_value(json!({"docs": ["b.md"], "stack": "Rust"})).unwrap();
    assert_eq!(
        patch.apply(&mut p),
        vec!["docs"],
        "an unchanged value is not a change"
    );
    assert_eq!(
        (p.stack.as_str(), p.docs.as_slice()),
        ("Rust", &["b.md".to_owned()][..])
    );
}

#[test]
fn a_proposal_body_is_json_or_a_text_fields_plain_text() {
    let dod = field_patch("definition_of_done", r#"["tests pass"]"#).unwrap();
    assert_eq!(dod.definition_of_done, Some(vec!["tests pass".to_owned()]));
    let stack = field_patch("stack", "Rust 1.93, axum").unwrap();
    assert_eq!(stack.stack.as_deref(), Some("Rust 1.93, axum"));
    assert!(
        field_patch("definition_of_done", "tests pass").is_err(),
        "not a list"
    );
    assert!(field_patch("merge_method", "\"octopus\"").is_err());
    assert!(
        field_patch("permission_mode", "\"sandboxed\"").is_err(),
        "not a profile field"
    );
    assert!(
        field_patch("nope", "1")
            .unwrap_err()
            .contains("definition_of_done")
    );
}

#[test]
fn the_budget_keeps_sections_in_order_and_names_the_rest() {
    let p = profile(json!({
        "stack": "Rust",
        "definition_of_done": ["tests pass", "PR merged"],
        "docs": ["Docs/Specs/api.md"],
        "environments": [{"name": "Prod", "url": "https://prod.example", "deploy": "owner"}],
    }));
    let all = fit(p.sections(vec![], &POLICIES), 4096);
    let text = all.text.unwrap();
    assert!(text.starts_with("# Project profile\n\n## definition of done\n\n- tests pass\n"));
    assert!(text.contains("- Prod (https://prod.example): only the owner deploys\n"));
    assert!(text.contains("- Permission mode: ask\n"));
    assert!(all.dropped.is_empty());

    let tight = fit(p.sections(vec![], &POLICIES), 120);
    assert_eq!(tight.kept[0], "definition_of_done");
    assert!(tight.dropped.contains(&"environments"), "{tight:?}");
    let text = tight.text.unwrap();
    let kept = &text["# Project profile\n\n".len()..text.rfind("Left out").unwrap()];
    assert!(kept.len() <= 120, "{kept}");
    assert!(
        text.ends_with(&format!(
            "Left out for size (read them with get_context): {}.\n",
            tight.dropped.join(", ")
        )),
        "{text}"
    );
    let none = fit(p.sections(vec![], &POLICIES), 0);
    assert!(none.kept.is_empty() && none.text.unwrap().contains("Left out for size"));
}
