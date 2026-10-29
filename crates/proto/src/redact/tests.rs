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
