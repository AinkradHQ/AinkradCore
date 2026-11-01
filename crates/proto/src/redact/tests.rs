use serde_json::json;

use super::*;

#[test]
fn every_shape_is_redacted_by_kind() {
    let r = Redactor::new();
    for (kind, secret) in PLANTED {
        let text = format!("before {secret} after");
        let out = r.text(&text);
        assert_eq!(out, format!("before [redacted:{kind}] after"), "{secret}");
    }
    // Header text around a bearer stays; the credential goes.
    assert_eq!(
        r.text("Authorization: bearer abcdefgh12345678"),
        "Authorization: [redacted:bearer]"
    );
    // An unterminated PEM block goes to the end.
    assert_eq!(
        r.text("key: -----BEGIN RSA PRIVATE KEY-----\nMIIE"),
        "key: [redacted:pem_block]"
    );
}

#[test]
fn ordinary_text_is_left_alone() {
    let r = Redactor::new();
    for text in [
        "task-list and risk-assessment-document-for-the-whole-team",
        "sk-short",
        "AKIAlower-case-is-not-a-key",
        "the bearer of bad news",
        "cit_run_42",
        "héllo wörld ✓ ghp_",
        "",
    ] {
        assert_eq!(r.text(text), text);
    }
}

#[test]
fn known_secrets_go_by_name_longest_first() {
    let mut r = Redactor::new();
    r.known("askpass", "hunter2-correct-horse");
    r.known("env:ANTHROPIC_API_KEY", "plainvalue-without-a-prefix");
    r.known("short", "1");
    r.known("inner", "hunter2-correct");
    let out =
        r.text("pw=hunter2-correct-horse key=plainvalue-without-a-prefix n=1 hunter2-correct!");
    assert_eq!(
        out,
        "pw=[redacted:askpass] key=[redacted:env:ANTHROPIC_API_KEY] n=1 [redacted:inner]!"
    );
}

#[test]
fn known_values_are_redacted_when_encoded_or_split() {
    let mut r = Redactor::new();
    r.known("session", "split-secret-41");
    assert!(!r.text("c3BsaXQtc2VjcmV0LTQx").contains("c3BsaXQ"));
    assert!(!r.text("73706c69742d7365637265742d3431").contains("73706c"));
    assert!(!r.stream_text("split-").contains("split-secret"));
    assert!(!r.stream_text("secret-41").contains("secret-41"));
}

#[test]
fn json_strings_and_keys_are_redacted() {
    let mut r = Redactor::new();
    r.known("run_token", "tok-123456789");
    let mut v = json!({
        "type": "tool_use",
        "input": {"command": "curl -H 'Authorization: Bearer abcdefgh12345678' x",
                  "env": ["tok-123456789", 7, null, true]},
        "AKIAIOSFODNN7EXAMPLE": 1,
    });
    r.json(&mut v);
    assert_eq!(
        v,
        json!({
            "type": "tool_use",
            "input": {"command": "curl -H 'Authorization: [redacted:bearer]' x",
                      "env": ["[redacted:run_token]", 7, null, true]},
            "[redacted:aws_key]": 1,
        })
    );
}

#[test]
fn text_files_are_redacted_and_counted_and_others_are_not_scanned() {
    let mut r = Redactor::new();
    r.known("askpass", "hunter2-correct-horse");
    let body = format!("{} pw=hunter2-correct-horse\n", PLANTED[0].1);
    let (out, count) = r.file("notes.MD", body.into_bytes());
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "[redacted:anthropic_key] pw=[redacted:askpass]\n"
    );
    assert_eq!(count, Some(2));
    // Not UTF-8: decoded lossily, still scanned.
    let (out, count) = r.file("x.log", b"\xff hunter2-correct-horse".to_vec());
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "\u{fffd} [redacted:askpass]"
    );
    assert_eq!(count, Some(1));
    let png = b"\x89PNG hunter2-correct-horse".to_vec();
    assert_eq!(r.file("shot.png", png.clone()), (png, None));
    assert!(!is_text("noext") && is_text("a.yml") && !is_text("a.pdf"));
}

#[test]
fn every_split_of_plain_and_encoded_values_is_withheld() {
    let value = "canary-password/with+bytes\\\"";
    let mut r = Redactor::new();
    r.known("canary", value);
    let json = serde_json::to_string(value).unwrap();
    for representation in [
        value.to_owned(),
        base64(value),
        hex(value),
        percent(value),
        json[1..json.len() - 1].to_owned(),
    ] {
        assert!(!r.text(&representation).contains(&representation));
        for split in 1..representation.len() {
            if !representation.is_char_boundary(split) {
                continue;
            }
            let out =
                r.stream_text(&representation[..split]) + &r.stream_text(&representation[split..]);
            assert!(
                !out.contains(&representation),
                "split {split} reconstructed a secret"
            );
            assert!(out.contains("[redacted:canary]"));
        }
    }
}

#[test]
fn a_secret_cannot_override_the_sandbox_manifest_or_a_loader() {
    for name in [
        "AINKRAD_SANDBOX_TMP",
        "AINKRAD_GUARD_PATHS",
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
        "PYTHONPATH",
    ] {
        assert!(!crate::v2::valid_secret_var(name), "accepted {name}");
    }
}

#[test]
fn fabricated_redaction_markers_do_not_disable_stream_filtering() {
    let mut r = Redactor::new();
    r.known("canary", "canary-password");
    assert!(!r.stream_text("[redacted:fake]canary-").ends_with("canary-"));
    assert!(
        !r.stream_text("password[redacted:fake]")
            .starts_with("password")
    );
}

#[test]
fn text_ending_in_a_secrets_first_characters_is_not_mangled() {
    let mut r = Redactor::new();
    r.known("tok", "sk-live-0123456789");
    // A message that happens to end with the secret's first letter or two stays intact.
    assert_eq!(r.stream_text("what is this"), "what is this");
    assert_eq!(r.stream_text("grass is s"), "grass is s");
    assert_eq!(r.stream_text("ends with sk"), "ends with sk");
    // A real prefix is still withheld.
    assert!(!r.stream_text("x sk-l").contains("sk-l"));
}

#[test]
fn base64_inside_a_longer_string_and_an_uppercase_copy_are_redacted() {
    // 17 bytes: not a multiple of 3, so every alignment gives different characters.
    let value = "zq83-plain-val-44";
    let mut r = Redactor::new();
    r.known("leased", value);
    for prefix in ["", "u:", "us:", "user:", "basic user:", "x"] {
        for suffix in ["", "!", "?x", "a", "Z", "~~"] {
            let raw = format!("{prefix}{value}{suffix}");
            for enc in [
                base64(&raw),
                base64(&raw).trim_end_matches('=').to_owned(),
                base64(&raw).replace('+', "-").replace('/', "_"),
            ] {
                let out = r.text(&format!("Authorization: {enc} end"));
                assert!(out.contains("[redacted:leased]"), "{raw:?}: {enc} -> {out}");
            }
        }
    }
    let shouted = r.text(&format!("{} here", value.to_uppercase()));
    assert!(!shouted.contains(&value.to_uppercase()), "{shouted}");
}

#[test]
fn a_lowercase_copy_of_a_mixed_case_value_is_redacted() {
    let mut r = Redactor::new();
    r.known("leased", "AbCd-EfGh-1234");
    assert!(!r.text("abcd-efgh-1234").contains("abcd"));
    assert!(!r.text("ABCD-EFGH-1234").contains("ABCD"));
    // And a long stream of near-misses stays linear: no quadratic prefix scan.
    let mut r = Redactor::new();
    r.known("leased", &"ab".repeat(2000));
    let started = std::time::Instant::now();
    for _ in 0..200 {
        let _ = r.stream_text(&"ab".repeat(1500));
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
