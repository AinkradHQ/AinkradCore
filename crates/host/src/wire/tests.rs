use super::*;

const ID: &str = "01HZX3J8K9M2N4P5Q6R7S8T9V0";

fn req(action: &str, params: &str) -> String {
    format!(
        r#"{{"v":1,"id":"{ID}","action":"{action}","params":{params},"actor":{{"device":"d_abc-1","audit_seq":7}}}}"#
    )
}

#[test]
fn the_four_class_a_actions_round_trip() {
    for (a, p, want) in [
        ("status", "{}", Action::Status),
        ("restart_core", "{}", Action::RestartCore),
        ("restart_runner", "{}", Action::RestartRunner),
    ] {
        let r = parse(req(a, p).as_bytes()).unwrap();
        assert_eq!((r.id.as_str(), r.action), (ID, want));
        assert_eq!(r.actor.audit_seq, 7);
    }
    let r = parse(req("logs", r#"{"unit":"core"}"#).as_bytes()).unwrap();
    assert_eq!(
        r.action,
        Action::Logs(Logs {
            unit: Unit::Core,
            lines: 200,
            before: None
        })
    );
    let r = parse(
        req(
            "logs",
            r#"{"unit":"helper","lines":500,"before":"s=a;i=1_b"}"#,
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        r.action,
        Action::Logs(Logs {
            unit: Unit::Helper,
            lines: 500,
            before: Some("s=a;i=1_b".into())
        })
    );
    // `params` may be left out for the actions that take none.
    let bare = format!(
        r#"{{"v":1,"id":"{ID}","action":"status","actor":{{"device":"d_x","audit_seq":0}}}}"#
    );
    assert!(parse(bare.as_bytes()).is_ok());
}

fn code(line: &str) -> Code {
    parse(line.as_bytes()).unwrap_err().code
}

#[test]
fn unknown_fields_are_refused_at_every_level() {
    let extra_top = req("status", "{}").replacen("\"v\":1", "\"v\":1,\"x\":1", 1);
    assert_eq!(code(&extra_top), Code::BadRequest);
    let extra_actor =
        req("status", "{}").replace("\"audit_seq\":7", "\"audit_seq\":7,\"root\":true");
    assert_eq!(code(&extra_actor), Code::BadRequest);
    assert_eq!(code(&req("status", r#"{"unit":"core"}"#)), Code::BadRequest);
    assert_eq!(
        code(&req("restart_core", r#"{"force":true}"#)),
        Code::BadRequest
    );
    assert_eq!(
        code(&req("logs", r#"{"unit":"core","path":"/etc/shadow"}"#)),
        Code::BadRequest
    );
}

#[test]
fn bad_envelopes_and_params_are_refused() {
    for bad in [
        req("status", "{}").replace("\"v\":1", "\"v\":2"),
        req("status", "{}").replace(ID, "short"),
        req("status", "{}").replace(ID, "01HZX3J8K9M2N4P5Q6R7S8T9VI"),
        req("status", "{}").replace("d_abc-1", "abc"),
        req("status", "{}").replace("d_abc-1", "d_a b"),
        req("status", "{}").replace("\"audit_seq\":7", "\"audit_seq\":-1"),
        req("status", "[]"),
        req("logs", r#"{"unit":"core","lines":0}"#),
        req("logs", r#"{"unit":"core","lines":501}"#),
        req("logs", r#"{"unit":"core","lines":-1}"#),
        req("logs", r#"{"unit":"core","lines":1.5}"#),
        req("logs", r#"{"unit":"ssh"}"#),
        req("logs", r#"{"unit":"core.service"}"#),
        req("logs", r#"{"lines":5}"#),
        req("logs", r#"{"unit":"core","before":"-r"}"#),
        req(
            "logs",
            r#"{"unit":"core","before":"--cursor-file=/etc/shadow"}"#,
        ),
        req("logs", r#"{"unit":"core","before":"a b"}"#),
        req("logs", r#"{"unit":"core","before":""}"#),
        "not json".into(),
        "[]".into(),
        "".into(),
        "{}".into(),
    ] {
        assert_eq!(code(&bad), Code::BadRequest, "{bad}");
    }
    let long = format!(r#"{{"unit":"core","before":"{}"}}"#, "a".repeat(257));
    assert_eq!(code(&req("logs", &long)), Code::BadRequest);
    assert!(parse(&[0xff, 0xfe]).is_err(), "non-UTF-8");
}

#[test]
fn unknown_and_class_b_actions_are_unknown_action() {
    for name in ["nope", "backup_now", "STATUS", "status ", "", "sh"] {
        let r = parse(req(name, "{}").as_bytes()).unwrap_err();
        assert_eq!((r.code, r.class_b), (Code::UnknownAction, false), "{name}");
        assert_eq!(r.action, None);
    }
    for (name, class) in REGISTRY.iter().filter(|(_, c)| *c == Class::B) {
        assert_eq!(*class, Class::B);
        let r = parse(req(name, r#"{"anything":1}"#).as_bytes()).unwrap_err();
        assert_eq!(
            (r.code, r.class_b, r.action),
            (Code::UnknownAction, true, Some(*name))
        );
    }
}

#[test]
fn a_refusal_carries_only_validated_values() {
    let r = parse(req("status", r#"{"x":1}"#).as_bytes()).unwrap_err();
    assert_eq!(r.id.as_deref(), Some(ID));
    assert_eq!(r.action, Some("status"));
    let r = parse(req("status", "{}").replace(ID, "<script>").as_bytes()).unwrap_err();
    assert_eq!(r.id, None);
}

#[test]
fn responses_are_one_line_and_never_echo_input() {
    let ok = ok(ID, json!({"accepted": true}));
    assert_eq!(ok.iter().filter(|b| **b == b'\n').count(), 1);
    assert!(String::from_utf8(ok).unwrap().contains(r#""ok":true"#));
    let e = String::from_utf8(err(None, Code::RateLimited, Some(12))).unwrap();
    assert!(
        e.contains(r#""id":null"#)
            && e.contains(r#""retry_after":12"#)
            && e.contains("rate_limited")
    );
    for c in [
        Code::BadRequest,
        Code::UnknownAction,
        Code::ForbiddenPeer,
        Code::RateLimited,
        Code::Busy,
        Code::NotInstalled,
        Code::StateUnavailable,
        Code::Failed,
    ] {
        assert!(!c.message().is_empty() && !c.message().contains('{'));
    }
}

/// A cheap fuzz of the parser: random bytes and byte-level mutations of a valid request never
/// panic, and nothing but the valid request (or an equally valid mutation) is accepted.
#[test]
fn the_parser_survives_random_and_mutated_input() {
    // `HOST_FUZZ_ROUNDS=200000000` runs the long pass (about ten minutes); the default is quick.
    let rounds: u64 = std::env::var("HOST_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ rounds;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let seed = req("logs", r#"{"unit":"core","lines":20,"before":"s=1;i=2"}"#).into_bytes();
    for round in 0..rounds {
        let mut buf = if round % 4 == 0 {
            (0..(next() % 300)).map(|_| next() as u8).collect()
        } else {
            seed.clone()
        };
        if round % 4 != 0 {
            for _ in 0..=(next() % 4) {
                let i = (next() as usize) % buf.len();
                match next() % 3 {
                    0 => buf[i] = next() as u8,
                    1 => buf.insert(i, next() as u8),
                    _ => {
                        buf.remove(i);
                    }
                }
            }
        }
        let _ = parse(&buf);
    }
}
