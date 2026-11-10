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

#[test]
fn spaces_around_the_separator_escaped_quotes_and_host_words() {
    assert_eq!(
        one("password = hunter2 next"),
        "password = [redacted:password] next"
    );
    assert_eq!(
        one("x \"token\" : \"abc def\" y"),
        "x \"token\" : [redacted:token] y"
    );
    assert_eq!(one("secret\t=\tvalue"), "secret\t=\t[redacted:secret]");
    // JSON that was itself put inside a string: escaped quotes around key and value.
    assert_eq!(
        one(r#"body={\"token\":\"ab\\\"c\",\"n\":1}"#),
        r#"body={\"token\":[redacted:token],\"n\":1}"#
    );
    // A quoted value with an escaped quote inside.
    assert_eq!(
        one(r#"password:"a\"b" ok"#),
        r#"password:[redacted:password] ok"#
    );
    // Host-only words (the shared pass is unchanged).
    assert_eq!(
        one("pwd=abc123 pass: xyz"),
        "pwd=[redacted:pwd] pass: [redacted:pass]"
    );
    assert_eq!(
        one("Cookie: sid=1; other=2 trailing\nnext"),
        "Cookie: [redacted:Cookie]\nnext"
    );
    assert_eq!(
        one("Set-Cookie: a=b; Path=/"),
        "Set-Cookie: [redacted:Set-Cookie]"
    );
    assert_eq!(one("bypass=1 compass: n"), "bypass=1 compass: n");
    assert_eq!(
        one("dial postgres://app:s3cret@db:5432/x and https://example.org/p"),
        "dial postgres://app:[redacted:url_password]@db:5432/x and https://example.org/p"
    );
    // A port followed by a stray `@` is read as user:password (the over-masking side).
    assert_eq!(
        one("see http://host:8080/a@b"),
        "see http://host:[redacted:url_password]@b"
    );
    assert_eq!(
        one("see http://host:8080/a and https://example.org"),
        "see http://host:8080/a and https://example.org"
    );
}

#[test]
fn the_shared_name_pass_is_not_changed_by_the_host_words() {
    use ainkrad_proto::redact::names::secret_name;
    for w in ["cookie", "pass", "pwd", "passphrase"] {
        assert!(!secret_name(w), "{w} stays a host-only word");
    }
}

#[test]
fn an_end_without_a_begin_masks_the_body_lines_before_it_and_stops_at_ordinary_text() {
    let mut page: Vec<String> = [
        "an ordinary line",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw",
        "ggSjAgEAAoIBAQC7VJTUt9Us8cKj",
        "-----END RSA PRIVATE KEY-----",
        "later",
        "-----BEGIN X-----",
        "y",
    ]
    .map(String::from)
    .to_vec();
    pem_across(&mut page);
    let out: Vec<&str> = page.iter().map(String::as_str).collect();
    assert_eq!(out, ["an ordinary line", PEM, PEM, PEM, "later", PEM, PEM]);
    // A lone END line a client printed hides nothing else on the page.
    let mut page: Vec<String> = ["a", "b is fine", "-----END X-----"]
        .map(String::from)
        .to_vec();
    pem_across(&mut page);
    assert_eq!(page, ["a", "b is fine", PEM]);
}

#[test]
fn the_last_begin_and_end_decide_and_a_second_block_in_one_entry_keeps_masking() {
    let mut page: Vec<String> = [
        "-----BEGIN A-----x-----END A----- mid -----BEGIN B-----",
        "body of b",
        "-----END B----- after",
        "plain",
    ]
    .map(String::from)
    .to_vec();
    pem_across(&mut page);
    assert_eq!(page[1], PEM, "B is still open");
    assert_eq!(page[2], PEM);
    assert_eq!(page[3], "plain");
    // END before BEGIN in one entry: the first block closes, the second opens.
    let mut page = vec![
        "-----END A----- z -----BEGIN B-----".to_owned(),
        "x".to_owned(),
    ];
    pem_across(&mut page);
    assert_eq!(page, [PEM, PEM]);
}

#[test]
fn long_prefixed_and_base64url_runs_are_masked() {
    let std64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
    let url = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us-cKj_";
    let long = format!("{std64}{std64}{std64}");
    assert_eq!(one(&format!("app[12]: {std64}")), format!("app[12]: {PEM}"));
    assert_eq!(one(url), PEM);
    assert_eq!(one(&long), PEM);
    assert_eq!(one(&format!("{std64}==")), PEM);
    assert_eq!(
        one("--------------------------------------------------------------------"),
        "-".repeat(68)
    );
    assert_eq!(
        one("/usr/lib/x86_64-linux-gnu/some/dir/file.so loaded"),
        "/usr/lib/x86_64-linux-gnu/some/dir/file.so loaded"
    );
}

#[test]
fn backslash_runs_cost_linear_time() {
    use std::time::{Duration, Instant};
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let run = "\\".repeat(1 << 20);
        let t = Instant::now();
        let names = (
            names_text(&format!("password:\"{run}")),
            names_text(&format!("password:\\\"{run}")),
            names_text(&format!("password:\"{run}\" tail")),
        );
        let names_took = t.elapsed();
        let t = Instant::now();
        let whole = one(&format!("password:\"{run}"));
        let _ = tx.send((names_took, names, t.elapsed(), whole));
    });
    let (names_took, names, whole_took, whole) = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("the redactor must not go quadratic on a run of backslashes");
    // The key=value pass alone is linear: well under a second even unoptimised.
    assert!(names_took < Duration::from_secs(1), "{names_took:?}");
    // The whole pipeline (shapes, runs, names) loosely: the quadratic version takes minutes.
    assert!(whole_took < Duration::from_secs(20), "{whole_took:?}");
    assert_eq!(names.0, "password:[redacted:password]");
    assert_eq!(names.1, "password:[redacted:password]");
    assert_eq!(names.2, "password:[redacted:password] tail");
    assert_eq!(whole, "password:[redacted:password]");
}

#[test]
fn an_even_backslash_run_before_a_quote_closes_the_string_and_an_odd_one_does_not() {
    // Two backslashes then a quote: an escaped backslash, then the closing quote.
    assert_eq!(
        one("password:\"a\\\\\" tail"),
        "password:[redacted:password] tail"
    );
    // One backslash then a quote: the quote is escaped, the string goes on.
    assert_eq!(
        one("password:\"a\\\" tail\" end"),
        "password:[redacted:password] end"
    );
}

#[test]
fn a_long_key_is_still_a_key() {
    let long = format!("SOME_{}_TOKEN", "VERY_".repeat(14));
    let out = one(&format!("{long}=secretvalue"));
    assert!(!out.contains("secretvalue"), "{out}");
    let out = one(&format!("{}client_secret=hunter2value", "a/".repeat(40)));
    assert!(!out.contains("hunter2value"), "{out}");
    let b64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
    assert_eq!(
        one(&format!("{b64}==")),
        PEM,
        "real padding is still masked"
    );
}

#[test]
fn passwords_with_odd_characters_and_scheme_less_credentials() {
    for pw in ["a/b", "a?b", "a#b", "a b", "a\"b", "p@ss"] {
        let out = one(&format!("dial postgres://app:{pw}@db:5432/x ok"));
        assert_eq!(
            out, "dial postgres://app:[redacted:url_password]@db:5432/x ok",
            "{pw}"
        );
    }
    assert_eq!(
        one("connect admin:hunter2@db.internal failed"),
        "connect admin:[redacted:url_password]@db.internal failed"
    );
    assert_eq!(
        one("mail bob@example.org and 12:30 ok"),
        "mail bob@example.org and 12:30 ok"
    );
}

#[test]
fn an_over_long_entry_is_cut_before_redaction_and_the_cut_is_marked() {
    let secret = format!("sk-ant-api03-{}", "Q".repeat(40));
    let line = format!("{} {secret}", "word ".repeat(PRE_CUT / 5 - 8));
    assert!(line.len() > PRE_CUT - 40 && line.len() < PRE_CUT + 100);
    let cut = pre_cut(format!("{line} {}", "x ".repeat(PRE_CUT)));
    assert!(cut.len() <= PRE_CUT + 20 && cut.ends_with("[redacted:cut]"));
    assert!(!one(&cut).contains("QQQQ"));
    assert_eq!(pre_cut("short".into()), "short");
    // A token cut in half leaves nothing of itself behind: the cut backs up to whitespace.
    let tok = format!("{} {}", "a ".repeat(PRE_CUT / 2 - 10), "T".repeat(2000));
    let cut = pre_cut(tok);
    assert!(!cut.contains("TTT"), "the front of the token is gone too");
}
