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
    for s in [
        Scope::Server,
        Scope::Company(CompanyId(1)),
        Scope::Project(ProjectId(3)),
        Scope::Runner(RunnerId(2)),
        Scope::Account(AccountId(4)),
    ] {
        assert_eq!(s.to_string().parse::<Scope>(), Ok(s));
        assert_eq!(Scope::of(s.kind(), s.id()), s);
    }
    for bad in [
        "",
        "company",
        "company:x",
        "company:0",
        "server:1",
        "team:1",
    ] {
        assert!(bad.parse::<Scope>().is_err(), "{bad}");
    }
}

#[test]
fn values_are_checked_against_bounds_and_scopes() {
    let cap = Key::RunTokenCap.spec();
    assert_eq!(cap.check(ScopeKind::Project, "5000"), Ok(5000));
    let low = cap.check(ScopeKind::Server, "999").unwrap_err();
    assert_eq!(low.code(), "out_of_bounds");
    assert_eq!(
        low.to_string(),
        "run.token_cap must be 1000..=100000000; 999 is out of bounds"
    );
    let wrong = cap.check(ScopeKind::Runner, "5000").unwrap_err();
    assert_eq!(wrong.code(), "wrong_scope");
    assert_eq!(
        wrong.to_string(),
        "run.token_cap cannot be set per runner; it is set per server, company, project"
    );
    for bad in ["1.5", "\"5000\"", "true", ""] {
        assert_eq!(
            cap.check(ScopeKind::Server, bad).unwrap_err().code(),
            "not_integer"
        );
    }
    let lease = Key::LeaseTtlSecs.spec();
    assert_eq!(lease.check(ScopeKind::Runner, "30"), Ok(30));
    assert!(lease.check(ScopeKind::Project, "30").is_err());
}

#[test]
fn the_most_specific_scope_wins() {
    let (p, c) = (Scope::Project(ProjectId(3)), Scope::Company(CompanyId(1)));
    let chain = chain(p, Some(CompanyId(1)));
    assert_eq!(chain, vec![p, c, Scope::Server]);
    let key = Key::StuckAfterSecs;
    assert_eq!(resolve(key, &chain, &[]), (600, None));
    let server = (Scope::Server, 900);
    assert_eq!(resolve(key, &chain, &[server]), (900, Some(Scope::Server)));
    let company = (c, 1200);
    assert_eq!(resolve(key, &chain, &[server, company]), (1200, Some(c)));
    let project = (p, 300);
    assert_eq!(
        resolve(key, &chain, &[server, project, company]),
        (300, Some(p))
    );
    // Another project's or company's value is not this one's.
    let other = [
        (Scope::Project(ProjectId(4)), 120),
        (Scope::Company(CompanyId(2)), 240),
    ];
    assert_eq!(resolve(key, &chain, &other), (600, None));
    // A row at a scope the key does not allow, or out of bounds, is passed over.
    let runner = Scope::Runner(RunnerId(2));
    assert_eq!(
        resolve(key, &[runner, Scope::Server], &[(runner, 120)]),
        (600, None)
    );
    assert_eq!(
        resolve(key, &chain, &[(p, 1), server]),
        (900, Some(Scope::Server))
    );
    // A company-and-server key read for a project uses the project's company.
    assert_eq!(
        resolve(Key::BudgetWarnPercent, &chain, &[(c, 70)]),
        (70, Some(c))
    );
}
