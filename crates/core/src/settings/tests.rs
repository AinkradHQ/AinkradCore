use super::*;

#[test]
fn the_registry_is_in_key_order_with_sane_rows() {
    for (i, spec) in REGISTRY.iter().enumerate() {
        assert_eq!(spec.key as usize, i, "{}", spec.name);
        assert_eq!(spec.key.spec().name, spec.name);
        assert_eq!(spec.name.parse::<Key>(), Ok(spec.key));
        assert!(
            spec.min <= spec.default && spec.default <= spec.max,
            "{}",
            spec.name
        );
        assert_eq!(
            spec.scopes.first(),
            Some(&ScopeKind::Server),
            "{}",
            spec.name
        );
        assert!(!spec.description.is_empty());
        let dupes = REGISTRY.iter().filter(|s| s.name == spec.name).count();
        assert_eq!(dupes, 1, "{}", spec.name);
    }
    assert_eq!(
        "nope".parse::<Key>(),
        Err(SettingError::UnknownKey("nope".to_owned()))
    );
}

#[test]
fn scopes_round_trip_as_text() {
    let s = Scope::Server;
    assert_eq!(s.to_string().parse::<Scope>(), Ok(s));
    assert_eq!(Scope::of(s.kind(), s.id()), Some(s));
    assert_eq!(Scope::of(ScopeKind::Server, 1), None);
    for bad in ["", "server:1", "company:1", "team:1"] {
        assert!(bad.parse::<Scope>().is_err(), "{bad}");
    }
}

#[test]
fn values_are_checked_against_bounds() {
    let burst = Key::ApiRequestBurst.spec();
    assert_eq!(burst.check(ScopeKind::Server, "500"), Ok(500));
    let low = burst.check(ScopeKind::Server, "9").unwrap_err();
    assert_eq!(low.code(), "out_of_bounds");
    assert_eq!(
        low.to_string(),
        "api.request_burst must be 10..=10000; 9 is out of bounds"
    );
    for bad in ["1.5", "\"500\"", "true", ""] {
        assert_eq!(
            burst.check(ScopeKind::Server, bad).unwrap_err().code(),
            "not_integer"
        );
    }
}

#[test]
fn a_stored_value_in_bounds_wins_over_the_default() {
    let key = Key::SchedulerTickSecs;
    let chain = [Scope::Server];
    assert_eq!(resolve(key, &chain, &[]), (10, None));
    let server = (Scope::Server, 30);
    assert_eq!(resolve(key, &chain, &[server]), (30, Some(Scope::Server)));
    // A value no longer in bounds is passed over.
    assert_eq!(resolve(key, &chain, &[(Scope::Server, 0)]), (10, None));
}
