use super::*;

#[test]
fn sizes_are_checked() {
    assert_eq!(size_of(None).unwrap(), None);
    let sz = |w, h| size_of(Some(&ComposeSize { w, h }));
    assert_eq!(sz(1440.0, 900.0).unwrap(), Some((1440.0, 900.0)));
    assert_eq!(sz(200.0, 4000.0).unwrap(), Some((200.0, 4000.0)));
    for (w, h) in [
        (199.0, 900.0),
        (1440.0, 4001.0),
        (f64::NAN, 900.0),
        (1440.0, f64::INFINITY),
        (-5.0, 900.0),
    ] {
        assert!(sz(w, h).is_err(), "{w} x {h}");
    }
}

#[test]
fn the_mode_is_checked_against_the_doc() {
    let req = |mode: Option<&str>, frame: Option<&str>, brand: Option<Brand>| NewCompose {
        prompt: "x".into(),
        count: None,
        size: None,
        mode: mode.map(str::to_owned),
        frame: frame.map(str::to_owned),
        brand,
    };
    let m = |r: NewCompose, k: Option<&str>| mode_of(&r, k);
    assert_eq!(
        m(req(None, None, None), Some("design")).unwrap(),
        Mode::Screens
    );
    assert_eq!(
        m(req(Some("screens"), None, None), Some("system")).unwrap(),
        Mode::Screens
    );
    assert_eq!(
        m(req(Some("system"), None, None), Some("system")).unwrap(),
        Mode::System
    );
    assert!(m(req(Some("system"), None, None), Some("design")).is_err());
    assert!(m(req(Some("system"), None, None), None).is_err());
    assert!(m(req(Some("tokens"), None, None), Some("system")).is_err());
    assert_eq!(
        m(
            req(Some("edit"), Some("n_aaaaaaaaaaaa"), None),
            Some("design")
        )
        .unwrap(),
        Mode::Edit
    );
    assert!(m(req(Some("edit"), None, None), Some("design")).is_err());
    assert!(m(req(Some("edit"), Some("frame-1"), None), Some("design")).is_err());
    let bad = Brand {
        colors: vec!["red".into()],
        name: None,
    };
    assert!(m(req(Some("system"), None, Some(bad)), Some("system")).is_err());
    let ok = Brand {
        colors: vec!["#2F7BEF".into()],
        name: Some("Acme".into()),
    };
    assert_eq!(brand_line(&ok).unwrap(), "\"Acme\", colours #2F7BEF");
    assert!(
        brand_line(&Brand {
            colors: vec![],
            name: None
        })
        .is_none()
    );
    assert_eq!(
        m(req(Some("system"), None, Some(ok)), Some("system")).unwrap(),
        Mode::System
    );
}

#[test]
fn a_compose_view_names_its_new_fields_only_when_set() {
    let v = ComposeView {
        id: "dc_x".into(),
        doc: "dd_x".into(),
        state: "done".into(),
        reason: String::new(),
        session: None,
        directions: vec![Direction {
            name: "A".into(),
            summary: String::new(),
            frame: None,
            screens: None,
        }],
        stage: None,
        flow: None,
    };
    let j = serde_json::to_value(&v).unwrap();
    assert!(
        j.get("stage").is_none()
            && j.get("flow").is_none()
            && j["directions"][0].get("screens").is_none()
    );
}
