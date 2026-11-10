use ainkrad_proto::redact::PLANTED;

use super::*;

#[test]
fn every_planted_shape_is_masked() {
    for (kind, secret) in PLANTED {
        assert_eq!(
            one(&format!("x {secret} y")),
            format!("x [redacted:{kind}] y"),
            "{secret}"
        );
    }
}

#[test]
fn secret_named_fields_are_masked_in_text_and_json() {
    assert_eq!(
        one("login password=hunter22 ok"),
        "login password=[redacted:password] ok"
    );
    assert_eq!(
        one("GET /x?api_key=abc123&y=1"),
        "GET /x?api_key=[redacted:api_key]&y=1"
    );
    assert_eq!(
        one("Authorization: Bearer abcdefgh12345678"),
        "Authorization: [redacted:Authorization]"
    );
    assert_eq!(
        one(r#"a "token":"s3cr3t value" b"#),
        r#"a "token":[redacted:token] b"#
    );
    assert_eq!(one("secret: plain"), "secret: [redacted:secret]");
    assert_eq!(
        one("key=scheduler.tick scope=read tokens_used=4"),
        "key=scheduler.tick scope=read tokens_used=4"
    );
    let j = one(
        r#"{"level":"INFO","fields":{"message":"user pass=1 password=zzz","db_password":"p"}}"#,
    );
    assert!(!j.contains("zzz") && !j.contains(":\"p\""), "{j}");
    assert!(j.contains("[redacted:db_password]"), "{j}");
    assert_eq!(one("12:30:45 started"), "12:30:45 started");
}

#[test]
fn a_pem_block_is_masked_across_entries() {
    let mut page: Vec<String> = [
        "before",
        "pre -----BEGIN OPENSSH PRIVATE KEY-----",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
        "-----END OPENSSH PRIVATE KEY-----",
        "after",
        "-----BEGIN CERTIFICATE-----",
        "never closed",
        "also masked",
    ]
    .map(String::from)
    .to_vec();
    pem_across(&mut page);
    let out: Vec<String> = page.iter().map(|t| one(t)).collect();
    assert_eq!(out[0], "before");
    assert_eq!(out[1], format!("pre {PEM}"));
    assert_eq!((out[2].as_str(), out[3].as_str()), (PEM, PEM));
    assert_eq!(out[4], "after");
    assert_eq!(
        (out[5].as_str(), out[6].as_str(), out[7].as_str()),
        (PEM, PEM, PEM)
    );
    // A whole block inside one entry is left to the shape pass.
    let mut one_entry = vec!["k -----BEGIN KEY-----\nAAAA\n-----END KEY----- z".to_owned()];
    pem_across(&mut one_entry);
    assert_eq!(one(&one_entry[0]), "k [redacted:pem_block] z");
}

#[test]
fn the_body_of_a_block_whose_begin_is_on_another_page_is_masked() {
    let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
    assert_eq!(body.len(), 64);
    assert_eq!(one(body), PEM);
    assert_eq!(
        one("an ordinary sentence of about sixty four characters, not base64!"),
        "an ordinary sentence of about sixty four characters, not base64!"
    );
}

#[test]
fn redaction_happens_before_the_cut() {
    let secret = format!("sk-ant-api03-{}", "A".repeat(40));
    for pad in [LINE_CAP - 30, LINE_CAP - 20, LINE_CAP - 8, LINE_CAP - 2] {
        let line = format!("{} {secret} tail", "x".repeat(pad));
        let out = cap(one(&line), LINE_CAP);
        assert!(
            !out.contains("sk-ant"),
            "pad {pad}: {}",
            &out[out.len() - 60..]
        );
        assert!(!out.contains("AAAA"), "pad {pad}");
    }
    assert_eq!(cap("é".repeat(5), 3), "é…", "on a character boundary");
    assert_eq!(cap("short".into(), 10), "short");
}
