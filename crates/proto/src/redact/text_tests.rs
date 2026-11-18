use super::*;

#[test]
fn secret_named_fields_are_masked_anywhere_in_a_line() {
    for (line, leaked) in [
        ("user=bob password=hunter2", "hunter2"),
        (r#"{"user":"bob","password":"hunter2"}"#, "hunter2"),
        ("DATABASE_URL=postgres://u:pw@h", ":pw@"),
    ] {
        let out = one(line);
        assert!(!out.contains(leaked), "{line} -> {out}");
    }
    assert!(one("user=bob password=hunter2").contains("user=bob"));
}
